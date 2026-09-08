import re
import time
import json
import os
import logging
import threading
import spacy
from transformers import pipeline, AutoTokenizer
from spellchecker import SpellChecker

# Local engine logger
logger = logging.getLogger("AXION-ENGINE")

class PrivacyEngine:
    """
    AXION Privacy Engine
    Hybrid de-identification system using SOTA Ettin-68M Transformers 
    and Grammatical Dependency Parsing (spaCy) for utility preservation.
    Dual-language support (English and Spanish).
    """
    
    def __init__(self):
        # 1. Semantic Layer: NVIDIA Ettin-68M (2025 SOTA)
        model_name = "kalyan-ks/ettin-68m-nemotron-pii"
        self.nlp = pipeline("token-classification", model=model_name, aggregation_strategy="simple")
        # Separate tokenizer for measuring chunk boundaries. Sharing the
        # pipeline's would make concurrent requests fight over the same Rust
        # tokenizer ("Already borrowed"), so it gets its own plus a lock.
        self._tokenizer = AutoTokenizer.from_pretrained(model_name)
        self._tok_lock = threading.Lock()
        
        # 2. Context Layer: spaCy Dependency Parser (Bilingual)
        self.spacy_nlp = {}
        try:
            self.spacy_nlp['en'] = spacy.load("en_core_web_sm")
        except Exception as e:
            logger.error(f"spaCy model 'en_core_web_sm' missing: {e}")
        try:
            self.spacy_nlp['es'] = spacy.load("es_core_news_sm")
        except Exception as e:
            logger.error(f"spaCy model 'es_core_news_sm' missing: {e}")
        
        # 3. Fuzzy Layer: Typo-robust trigger detection (Bilingual)
        self.spell = {
            'en': SpellChecker(language='en'),
            'es': SpellChecker(language='es')
        }
        
        # Load Linguistic Rules (Bilingual)
        self.rules = {'en': {}, 'es': {}}
        for lang in ['en', 'es']:
            rules_path = os.path.join(os.path.dirname(__file__), 'rules', f'{lang}_rules.json')
            try:
                with open(rules_path, 'r') as f:
                    r = json.load(f)
                    self.rules[lang] = {
                        'verbs': set(r.get('SENSITIVE_VERBS', [])),
                        'pronouns': set(r.get('SENSITIVE_PRONOUNS', [])),
                        'utility': set(r.get('UTILITY_VERBS', [])),
                        'triggers': set(r.get('SENSITIVE_TRIGGERS', []))
                    }
            except Exception as e:
                logger.error(f"Missing rules for {lang}: {e}")

        # 4. Regex Layer: Zero-Trust deterministic fallback
        self.patterns = {
            # Standard PII
            'EMAIL': r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+',
            'DNI': r'\d{8}[A-Za-z]',
            'PHONE': r'(?:\+\d{1,3}[- ]?)?\(?\d{3}\)?[- ]?\d{3}[- ]?\d{3,4}',
            'CREDIT_CARD': r'\b(?:\d{4}[- ]?){3}\d{4}\b',
            'IBAN': r'\b[A-Za-z]{2}\d{2}[ ]?\d{4}[ ]?\d{4}[ ]?\d{4}[ ]?\d{4}[ ]?\d{1,4}\b',
            'PRICE': r'(?:[€$|]|GBP|USD|EUR|euros)\s?\d+(?:[.,]\d{2})?|\d+(?:[.,]\d{2})?\s?(?:[€$|]|GBP|USD|EUR|euros)',
            'ID': r'\b[A-Za-z]{1,2}\d{6,9}\b',
            'FRAGMENTED_ID': r'\d(?:\s?[-_.]?\s?\d){4,}',
            # P0 security patches (2026-06): credentials and tokens that an LLM proxy must block
            'CREDENTIAL': r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b'                                       # AWS access key ID
                          r'|xox[baprs]-[A-Za-z0-9-]{10,}'                                       # Slack token
                          r'|sk-(?:proj-|ant-api\d+-)?[A-Za-z0-9_\-]{20,}'                       # OpenAI / Anthropic
                          r'|AIza[0-9A-Za-z_\-]{35}'                                             # Google API key
                          r'|ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|ghs_[A-Za-z0-9]{36}'        # GitHub
                          r'|eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+'            # JWT
                          r'|T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{20,}',                     # Slack webhook path
            'BEARER_TOKEN': r'(?i)bearer\s+[A-Za-z0-9._\-/+=]{20,}',
            'DB_URL': r'(?:postgres|postgresql|mysql|mongodb|mongodb\+srv|redis|amqp)://[^\s\'"<>]+',
            'PRIVATE_KEY_BLOCK': r'-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----',
            'GENERIC_SECRET': r'(?i)(?:api[_-]?key|apikey|secret|password|passwd|pwd|token)\s*[:=]\s*["\']?([A-Za-z0-9._\-/+=]{12,})'
        }

        # PII Classification Groups
        self.always_mask = {'NAME', 'EMAIL', 'PHONE', 'CREDIT_CARD', 'IBAN', 'DNI', 'ID',
                            'FRAGMENTED_ID', 'ADDR',
                            # P0 credentials — always mask, never preserve
                            'CREDENTIAL', 'BEARER_TOKEN', 'DB_URL', 'PRIVATE_KEY_BLOCK',
                            'GENERIC_SECRET'}
        self.contextual = {'LOC', 'ORG', 'FIN', 'DATE', 'JOB', 'INFO'}

        # The transformer silently truncates past its 512-token window, so long
        # inputs are split with overlap. Windows are measured in real tokens, not
        # characters: token density varies enough between languages and content
        # that a fixed character width truncates without any error.
        self._MAX_TOKENS = 400
        self._TOKEN_OVERLAP = 64

        # Label Normalization Map
        self.tag_map = {
            'PERSON': 'NAME', 'GIVENNAME': 'NAME', 'SURNAME': 'NAME', 'USER_NAME': 'NAME',
            'FIRST_NAME': 'NAME', 'LAST_NAME': 'NAME', 'USERNAME': 'NAME', 'FULLNAME': 'NAME',
            'LOCATION': 'LOC', 'CITY': 'LOC', 'COUNTRY': 'LOC', 'STATE': 'LOC', 'COUNTY': 'LOC',
            'STREET_ADDRESS': 'ADDR', 'BUILDING_NUMBER': 'ADDR',
            'PHONENUMBER': 'PHONE', 'PHONE_NUMBER': 'PHONE', 'TEL': 'PHONE',
            'CREDITCARD': 'FIN', 'IBAN': 'FIN', 'PRICE': 'FIN', 'AMOUNT': 'FIN',
            'BANK_ROUTING_NUMBER': 'FIN', 'ACCOUNT_NUMBER': 'FIN', 'ROUTING_NUMBER': 'FIN',
            'ORGANIZATION': 'ORG', 'COMPANY': 'ORG', 'JOBTITLE': 'JOB',
            'COMPANY_NAME': 'ORG', 'ORG_NAME': 'ORG', 'EMPLOYER': 'ORG',
            'NATIONAL_ID': 'DNI', 'ID_NUMBER': 'DNI', 'PASSPORT': 'DNI',
        }
        
        # Prepositions the model often swallows into a span ("en Aragon"),
        # which then re-emerge duplicated after rehydration.
        self._leading_stop = {'en', 'a', 'al', 'desde', 'hacia', 'hasta', 'con',
                              'por', 'para', 'sobre', 'in', 'at', 'on', 'from', 'into'}

        # Stop words for ultra-fast language detection heuristic
        self.es_stop = {'el', 'la', 'de', 'que', 'en', 'es', 'mi', 'yo', 'por', 'con'}

    def _detect_language(self, text: str) -> str:
        """Ultra-fast zero-latency heuristic language detector."""
        words = set(re.findall(r'\b[a-z]{1,4}\b', text.lower()))
        if len(words.intersection(self.es_stop)) >= 1:
            return 'es'
        return 'en'

    def _evaluate_grammatical_utility(self, text, start, end, label, lang):
        """Analyzes SVO relation to distinguish personal disclosure from task queries."""
        nlp = self.spacy_nlp.get(lang)
        rule_set = self.rules.get(lang)
        
        if not nlp or not rule_set or label not in self.contextual:
            return False

        doc = nlp(text)
        tokens = [t for t in doc if max(t.idx, start) < min(t.idx + len(t.text), end)]
        
        for t in tokens:
            curr = t
            for _ in range(3): # Max depth for efficiency
                head = curr.head
                # Possessive markers (supports Spanish 'det' too, like "mi casa")
                if any(c.dep_ in ["poss", "det"] and c.text.lower() in rule_set['pronouns'] for c in head.children):
                    return False
                # Trace to verb
                if head.pos_ == "ADP": head = head.head
                lemma = head.lemma_.lower()
                # Resolve subject
                subject = next((c.text.lower() for c in head.children if "subj" in c.dep_), "")
                # Final decision
                if subject in rule_set['pronouns'] and lemma in rule_set['verbs']: return False
                if lemma in rule_set['utility']: return True
                if head == curr: break
                curr = head
        return False

    def _check_fuzzy_triggers(self, text, lang):
        """Checks if the text contains misspelled sensitive words."""
        checker = self.spell.get(lang)
        rule_set = self.rules.get(lang)
        if not checker or not rule_set:
            return False
            
        words = re.findall(r'[a-zA-Záéíóúñ]+', text.lower())
        for w in words:
            if len(w) < 3:
                continue
            corrected = checker.correction(w)
            if corrected and corrected != w and corrected in rule_set['triggers']:
                return True
        return False

    def _chunk(self, text: str):
        """Splits text into (offset, chunk) pairs that fit the model's token window."""
        with self._tok_lock:
            enc = self._tokenizer(text, add_special_tokens=False, return_offsets_mapping=True)
        offsets = [o for o in enc['offset_mapping'] if o[1] > o[0]]
        if len(offsets) <= self._MAX_TOKENS:
            return [(0, text)]

        chunks = []
        step = self._MAX_TOKENS - self._TOKEN_OVERLAP
        for i in range(0, len(offsets), step):
            window = offsets[i:i + self._MAX_TOKENS]
            start, end = window[0][0], window[-1][1]
            chunks.append((start, text[start:end]))
            if i + self._MAX_TOKENS >= len(offsets):
                break
        return chunks

    def anonymize(self, text: str):
        """Main masking pipeline."""
        found = []
        metrics = {}
        
        lang = self._detect_language(text)
        
        # 1. Regex Pass
        t0 = time.perf_counter()
        for label, pat in self.patterns.items():
            for m in re.finditer(pat, text):
                found.append({'start': m.start(), 'end': m.end(), 'type': label, 'score': 1.0})
        metrics['regex_time_ms'] = (time.perf_counter() - t0) * 1000
        
        # 2. SOTA AI Pass — with chunking for long inputs (P0 patch)
        t1 = time.perf_counter()
        threshold = 0.30 if lang == 'es' else 0.50
        for offset, chunk in self._chunk(text):
            for ent in self.nlp(chunk):
                score = float(ent.get('score', 0))
                if score >= threshold:
                    label = self.tag_map.get(ent['entity_group'].upper(), ent['entity_group'].upper())
                    found.append({'start': ent['start'] + offset,
                                  'end': ent['end'] + offset,
                                  'type': label, 'score': score})
        metrics['ai_model_time_ms'] = (time.perf_counter() - t1) * 1000

        # Span normalisation. The model returns raw sub-word offsets, which need
        # three corrections before they can be used as masking boundaries.
        for f in found:
            # a) Drop surrounding blanks so the token does not eat the separating
            #    space ("es <EMAIL_0>", not "es<EMAIL_0>").
            while f['start'] < f['end'] and text[f['start']].isspace():
                f['start'] += 1
            while f['end'] > f['start'] and text[f['end'] - 1].isspace():
                f['end'] -= 1
            # b) Grow to whole words. A span can cover only part of a token
            #    ("AS|ML"), which would leave half an identifier in the clear.
            while f['start'] > 0 and text[f['start'] - 1].isalnum() and text[f['start']].isalnum():
                f['start'] -= 1
            while f['end'] < len(text) and text[f['end']].isalnum() and text[f['end'] - 1].isalnum():
                f['end'] += 1
            # c) Shed a leading preposition, otherwise "en Aragon" rehydrates
            #    into "en en Aragon".
            head = re.match(r'([^\W\d_]+)\s+', text[f['start']:f['end']])
            if head and head.group(1).lower() in self._leading_stop:
                f['start'] += head.end()
        # A bare preposition is never PII on its own; left in, it merges with the
        # entity next to it and drags the word into the token.
        found = [f for f in found if f['end'] > f['start']
                 and text[f['start']:f['end']].lower() not in self._leading_stop]

        # 3. Fuzzy trigger check
        has_fuzzy_trigger = self._check_fuzzy_triggers(text, lang)

        # 4. Filtering & SVO Analysis
        if has_fuzzy_trigger:
            processed = list(found)
        else:
            processed = [f for f in found if f['type'] in self.always_mask or not self._evaluate_grammatical_utility(text, f['start'], f['end'], f['type'], lang)]

        # 4b. Occurrence propagation. Model recall is not uniform across a long
        # text: the same name can be caught in one sentence and missed in the
        # next, which leaks it. Once a string is classified as PII, every other
        # literal occurrence of it is masked as well.
        seen = {}
        for f in processed:
            frag = text[f['start']:f['end']].strip()
            if len(frag) >= 4:
                seen.setdefault(frag, f['type'])
        for frag, label in seen.items():
            # Anchor on word boundaries, otherwise a short fragment matches
            # inside ordinary words ("mar" turning "llamare" into "lla<X>e").
            pre = r'(?<!\w)' if frag[0].isalnum() or frag[0] == '_' else ''
            post = r'(?!\w)' if frag[-1].isalnum() or frag[-1] == '_' else ''
            for m in re.finditer(pre + re.escape(frag) + post, text):
                processed.append({'start': m.start(), 'end': m.end(),
                                  'type': label, 'score': 1.0})

        # 5. Greedy Merging & Conflict Resolution
        merged = []
        if processed:
            s = sorted(processed, key=lambda x: x['start'])
            curr = s[0]
            for i in range(1, len(s)):
                nxt = s[i]
                # Only bridge a gap made of blanks or hyphens ("Ana Ruiz",
                # "612 345 678"). The model emits sub-word fragments, and
                # allowing punctuation here chained them across commas until a
                # whole sentence collapsed into a single token.
                gap = text[curr['end']:nxt['start']]
                if nxt['start'] <= curr['end'] or re.fullmatch(r"[\s\-]{1,3}", gap):
                    # Regex entities (score=1.0) take type priority over AI entities
                    if nxt['score'] > curr['score']:
                        curr['type'] = nxt['type']
                    curr['end'] = max(curr['end'], nxt['end'])
                else:
                    merged.append(curr); curr = nxt
            merged.append(curr)

        final = []
        last_end = -1
        for ent in sorted(merged, key=lambda x: (x['start'], -(x['end'] - x['start']))):
            if ent['start'] >= last_end:
                final.append(ent); last_end = ent['end']

        # 6. Replacement
        final = sorted(final, key=lambda x: x['start'], reverse=True)
        mapping, anon = {}, text
        for i, ent in enumerate(final):
            token = f"<{ent['type']}_{i}>"
            mapping[token] = text[ent['start']:ent['end']]
            anon = anon[:ent['start']] + token + anon[ent['end']:]
            ent.update({'token': token, 'original': mapping[token]})
            
        return anon, mapping, metrics, final

    def deanonymize(self, response, mapping: dict) -> str:
        """
        Restores PII tokens in response using precise regex matching.
        Ensures tokens are replaced as whole units to avoid accidental collisions.
        """
        if hasattr(response, 'content'):
            content = response.content
            if isinstance(content, list):
                text = ''.join(
                    b.get('text', '') if isinstance(b, dict) else str(b)
                    for b in content
                )
            else:
                text = str(content)
        else:
            text = str(response)

        # Longest first, so <NAME_10> is never clipped by <NAME_1>.
        # Plain string replacement on purpose: re.sub() would read escape
        # sequences in the replacement, so restoring a value that contains a
        # backslash (a Windows path, say) raised or silently corrupted it.
        for tok in sorted(mapping, key=len, reverse=True):
            text = text.replace(tok, mapping[tok])

        return text
