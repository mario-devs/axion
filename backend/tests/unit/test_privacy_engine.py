"""
Comprehensive test suite for the AXION Privacy Engine.
Validated for Software Engineering (Rama IS) Thesis Defense.
"""
import pytest
from unittest.mock import patch, MagicMock
import sys, os

# Ensure src is in path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

@pytest.fixture
def engine():
    """PrivacyEngine with mocked transformer for fast logic testing."""
    with patch('src.engine.anonymizer.pipeline') as mock_pipe, \
         patch('src.engine.anonymizer.SpellChecker') as mock_spell_cls:
        mock_nlp = MagicMock(return_value=[])
        mock_pipe.return_value = mock_nlp
        mock_checker = MagicMock()
        mock_checker.correction.side_effect = lambda w: w 
        mock_spell_cls.return_value = mock_checker

        from src.engine.anonymizer import PrivacyEngine
        eng = PrivacyEngine()
        eng.nlp = mock_nlp
        eng.spell = mock_checker
        yield eng

def _set_ai(engine, entities):
    engine.nlp.return_value = entities

# ===========================================================================
# 1. REGEX DETECTION (Zero-Trust Layer)
# ===========================================================================

class TestRegexDetection:

    def test_email(self, engine):
        text = "Contact me at elena.marquez@ejemplo.com"
        anon, mapping, _, _ = engine.anonymize(text)
        assert "elena.marquez@ejemplo.com" not in anon
        assert "<EMAIL_0>" in anon

    def test_dni(self, engine):
        text = "Mi DNI es 12345678Z."
        anon, _, _, _ = engine.anonymize(text)
        assert "12345678Z" not in anon

    def test_phone(self, engine):
        text = "Call +34 600 123 456."
        anon, _, _, _ = engine.anonymize(text)
        assert "600 123 456" not in anon

    def test_credit_card(self, engine):
        text = "Paid with 4111-1111-1111-1111."
        anon, _, _, _ = engine.anonymize(text)
        assert "4111-1111-1111-1111" not in anon

    def test_iban(self, engine):
        text = "Bank: ES21 1234 5678 9012 3456 7890"
        anon, _, _, _ = engine.anonymize(text)
        assert "ES21 1234" not in anon

# ===========================================================================
# 2. UTILITY VS PRIVACY (The "Big Picture" Challenge)
# ===========================================================================

class TestUtilityPrivacyBalance:
    
    def test_geographic_utility_preserved(self, engine):
        """'Routes in Aragon' -> Aragon is utility context, should NOT be masked."""
        text = "What are the best hiking routes in Aragon?"
        _set_ai(engine, [{'entity_group': 'CITY', 'start': 35, 'end': 41, 'score': 0.9, 'word': 'Aragon'}])
        anon, _, _, _ = engine.anonymize(text)
        assert "Aragon" in anon

    def test_geographic_privacy_masked(self, engine):
        """'I live in Aragon' -> Aragon is personal sensitive data, SHOULD be masked."""
        text = "I live in Aragon."
        _set_ai(engine, [{'entity_group': 'CITY', 'start': 10, 'end': 16, 'score': 0.9, 'word': 'Aragon'}])
        anon, _, _, _ = engine.anonymize(text)
        assert "Aragon" not in anon
        assert "<LOC_0>" in anon

    def test_organization_utility_preserved(self, engine):
        """'Info about ASML' -> ASML is public knowledge entity."""
        text = "Tell me about ASML."
        _set_ai(engine, [{'entity_group': 'COMPANY', 'start': 14, 'end': 18, 'score': 0.9, 'word': 'ASML'}])
        anon, _, _, _ = engine.anonymize(text)
        assert "ASML" in anon

    def test_organization_privacy_masked(self, engine):
        """'I work at ASML' -> Trigger 'work at' makes it sensitive."""
        text = "I work at ASML."
        _set_ai(engine, [{'entity_group': 'COMPANY', 'start': 10, 'end': 14, 'score': 0.9, 'word': 'ASML'}])
        anon, _, _, _ = engine.anonymize(text)
        assert "ASML" not in anon

    def test_spanish_geographic_privacy_masked(self, engine):
        """'Yo vivo en Madrid' -> Madrid is sensitive data."""
        text = "Yo vivo en Madrid."
        _set_ai(engine, [{'entity_group': 'CITY', 'start': 11, 'end': 17, 'score': 0.9, 'word': 'Madrid'}])
        anon, _, _, _ = engine.anonymize(text)
        assert "Madrid" not in anon
        assert "<LOC_0>" in anon

    def test_spanish_geographic_utility_preserved(self, engine):
        """'El clima en Madrid' -> Madrid is utility context."""
        text = "El clima en Madrid."
        _set_ai(engine, [{'entity_group': 'CITY', 'start': 12, 'end': 18, 'score': 0.9, 'word': 'Madrid'}])
        anon, _, _, _ = engine.anonymize(text)
        assert "Madrid" in anon

# ===========================================================================
# 3. ADVERSARIAL & FUZZY ROBUSTNESS
# ===========================================================================

class TestAdversarialRobustness:

    def test_fragmented_id_spaced(self, engine):
        """'1 - 2 - 3' pattern should be caught by regex."""
        text = "Secret code: 1 - 2 - 3 - 4 - 5"
        anon, _, _, _ = engine.anonymize(text)
        assert "1 - 2 - 3" not in anon

    def test_fuzzy_misspelled_trigger(self, engine):
        """'addres' corrected to 'address' should trigger sensitive mode."""
        engine.spell.correction.side_effect = lambda w: 'address' if w == 'addres' else w
        text = "My addres: Madrid"
        _set_ai(engine, [{'entity_group': 'CITY', 'start': 11, 'end': 17, 'score': 0.5, 'word': 'Madrid'}])
        anon, _, _, _ = engine.anonymize(text)
        assert "Madrid" not in anon

# ===========================================================================
# 4. CORE LOGIC INTEGRITY
# ===========================================================================

class TestCoreLogic:

    def test_aggressive_merging(self, engine):
        """'Ra' + 'ul' -> '<NAME_0>'."""
        text = "Raul is here."
        _set_ai(engine, [
            {'entity_group': 'PERSON', 'start': 0, 'end': 2, 'score': 0.9, 'word': 'Ra'},
            {'entity_group': 'PERSON', 'start': 2, 'end': 4, 'score': 0.9, 'word': 'ul'}
        ])
        anon, mapping, _, _ = engine.anonymize(text)
        assert len(mapping) == 1
        assert "Raul" in mapping.values()

    def test_reverse_replacement_stability(self, engine):
        """Masking 'Bo' shouldn't break offset for 'Alexander'."""
        text = "Bo and Alexander."
        _set_ai(engine, [
            {'entity_group': 'PERSON', 'start': 0, 'end': 2, 'score': 0.9, 'word': 'Bo'},
            {'entity_group': 'PERSON', 'start': 7, 'end': 16, 'score': 0.9, 'word': 'Alexander'}
        ])
        anon, _, _, _ = engine.anonymize(text)
        assert "<NAME_1> and <NAME_0>" in anon or "<NAME_0> and <NAME_1>" in anon
        assert "Bo" not in anon
        assert "Alexander" not in anon
