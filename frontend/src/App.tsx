import React, { useState, useEffect, useRef } from 'react';
import axios from 'axios';
import { motion, AnimatePresence } from 'framer-motion';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import {
  Send,
  ShieldCheck,
  Activity,
  ChevronRight,
  Lock,
  Plus,
  LayoutDashboard,
  Sun,
  Moon,
  Zap,
  Info,
  Trash2
} from 'lucide-react';
import { v4 as uuidv4 } from 'uuid';
import './App.css';

// En `npm run dev` el proxy de Vite reescribe /api -> backend.
// En el build de Docker no hay proxy, así que la URL se inyecta al compilar.
const API_BASE = import.meta.env.VITE_API_URL || '/api';

interface Entity {
  token: string;
  type: string;
  original: string;
}

interface Metrics {
  regex_time_ms: number;
  ai_model_time_ms: number;
}

interface Message {
  id: string;
  type: 'user' | 'bot';
  text: string;
  maskedText?: string;
  entities?: Entity[];
  metrics?: Metrics;
  timestamp: Date;
}

interface ChatSession {
  id: string;
  title: string;
  messages: Message[];
}

const AXION: React.FC = () => {
  const [sessions, setSessions] = useState<ChatSession[]>(() => {
    const saved = localStorage.getItem('axion_sessions');
    return saved ? JSON.parse(saved) : [{ id: uuidv4(), title: 'New Conversation', messages: [] }];
  });
  const [activeSessionId, setActiveSessionId] = useState(sessions[0].id);
  const [input, setInput] = useState('');
  const [isAuditOpen, setIsAuditOpen] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const provider = 'google';
  const [theme, setTheme] = useState<'light' | 'dark'>(() => 
    (localStorage.getItem('axion_theme') as 'light' | 'dark') || 'light'
  );
  
  const scrollRef = useRef<HTMLDivElement>(null);
  const activeSession = sessions.find(s => s.id === activeSessionId) || sessions[0];
  const lastBotMessage = [...activeSession.messages].reverse().find(m => m.type === 'bot');

  useEffect(() => {
    localStorage.setItem('axion_sessions', JSON.stringify(sessions));
  }, [sessions]);

  useEffect(() => {
    localStorage.setItem('axion_theme', theme);
    document.documentElement.setAttribute('data-theme', theme);
  }, [theme]);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [activeSession.messages]);

  const handleSend = async () => {
    if (!input.trim() || isLoading) return;

    const userMsg: Message = {
      id: uuidv4(),
      type: 'user',
      text: input,
      timestamp: new Date()
    };

    const currentMessages = [...activeSession.messages, userMsg];
    updateSession(activeSessionId, currentMessages);
    setInput('');
    setIsLoading(true);

    try {
      const response = await axios.post(`${API_BASE}/chat`, {
        message: input
      }, {
        params: { provider },
        headers: { 'X-Session-ID': activeSessionId }
      });

      const botMsg: Message = {
        id: uuidv4(),
        type: 'bot',
        text: response.data.response,
        maskedText: response.data.masked_text,
        entities: response.data.entities,
        metrics: response.data.metrics,
        timestamp: new Date()
      };

      updateSession(activeSessionId, [...currentMessages, botMsg]);
      
      if (botMsg.entities && botMsg.entities.length > 0 && !isAuditOpen) {
        setIsAuditOpen(true);
      }
    } catch (error) {
      setErrorMsg("AXION: Connection to secure node lost. Verify backend is running.");
    } finally {
      setIsLoading(false);
    }
  };

  const updateSession = (sid: string, msgs: Message[]) => {
    setSessions(prev => prev.map(s => {
      if (s.id === sid) {
        const title = s.title === 'New Conversation' && msgs.length > 0 ? msgs[0].text.substring(0, 25) + '...' : s.title;
        return { ...s, messages: msgs, title };
      }
      return s;
    }));
  };

  const startNewChat = () => {
    const newSession = { id: uuidv4(), title: 'New Conversation', messages: [] };
    setSessions(prev => [newSession, ...prev]);
    setActiveSessionId(newSession.id);
    setErrorMsg(null);
  };

  const clearAllSessions = () => {
    const fresh = { id: uuidv4(), title: 'New Conversation', messages: [] };
    setSessions([fresh]);
    setActiveSessionId(fresh.id);
    setErrorMsg(null);
    localStorage.removeItem('axion_sessions');
  };

  const deleteSession = (e: React.MouseEvent, sid: string) => {
    e.stopPropagation();
    setSessions(prev => {
      const remaining = prev.filter(s => s.id !== sid);
      if (remaining.length === 0) {
        const fresh = { id: uuidv4(), title: 'New Conversation', messages: [] };
        setActiveSessionId(fresh.id);
        return [fresh];
      }
      if (sid === activeSessionId) setActiveSessionId(remaining[0].id);
      return remaining;
    });
  };

  return (
    <div className="app-container">
      <aside className="sidebar">
        <div className="sidebar-inner">
          <button className="new-chat-btn" onClick={startNewChat}>
            <Plus size={16} /> New Session
          </button>
          <button className="clear-all-btn" onClick={clearAllSessions} title="Clear all sessions">
            <Trash2 size={12} /> Clear all
          </button>
          <div className="session-list">
            {sessions.map(s => (
              <div
                key={s.id}
                className={`session-item ${s.id === activeSessionId ? 'active' : ''}`}
                onClick={() => { setActiveSessionId(s.id); setErrorMsg(null); }}
              >
                <span className="session-title">{s.title}</span>
                <button
                  className="session-delete"
                  onClick={(e) => deleteSession(e, s.id)}
                  title="Delete session"
                >
                  <Trash2 size={12} />
                </button>
              </div>
            ))}
          </div>
        </div>
      </aside>

      <main className="main-chat">
        <header className="chat-header">
          <div className="brand-box">
            <h1>AXION</h1>
            <span>Private AI Chatbot</span>
          </div>
          <div className="controls">
            <button className="theme-toggle" onClick={() => setTheme(theme === 'light' ? 'dark' : 'light')}>
              {theme === 'light' ? <Moon size={16} /> : <Sun size={16} />}
            </button>
            <span className="provider-label">Gemini Flash</span>
            <button 
              className={`audit-toggle ${isAuditOpen ? 'active' : ''}`}
              onClick={() => setIsAuditOpen(!isAuditOpen)}
            >
              <LayoutDashboard size={18} />
            </button>
          </div>
        </header>

        <div className="messages-flow" ref={scrollRef}>
          {activeSession.messages.length === 0 && !errorMsg && (
            <div className="welcome-state">
              <ShieldCheck size={32} />
              <p>Secure Node Established.</p>
            </div>
          )}
          <AnimatePresence>
            {activeSession.messages.map((msg) => (
              <motion.div
                key={msg.id}
                className={`msg-box ${msg.type}`}
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
              >
                <div className="msg-bubble">
                  <ReactMarkdown remarkPlugins={[remarkGfm]}>
                    {msg.text}
                  </ReactMarkdown>
                </div>
                {msg.type === 'bot' && msg.metrics && (
                  <div className="msg-info">
                    <Zap size={10} /> {(msg.metrics.regex_time_ms + msg.metrics.ai_model_time_ms).toFixed(1)}ms protection
                  </div>
                )}
              </motion.div>
            ))}
          </AnimatePresence>
          {isLoading && (
            <div className="pulse-loader">
              <div className="pulse-dot" />
              <div className="pulse-dot" />
            </div>
          )}
          {errorMsg && (
            <div className="error-toast" onClick={() => setErrorMsg(null)}>
              {errorMsg} ✕
            </div>
          )}
        </div>

        <footer className="chat-footer">
          <div className="input-field">
            <textarea
              placeholder="Message securely..."
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && !e.shiftKey && handleSend()}
              rows={1}
            />
            <button className="action-send" onClick={handleSend} disabled={!input.trim() || isLoading}>
              <Send size={18} />
            </button>
          </div>
          <div className="security-tag">
            <Lock size={10} /> Local De-identification Active
          </div>
        </footer>
      </main>

      <AnimatePresence>
        {isAuditOpen && (
          <motion.aside 
            className="audit-panel"
            initial={{ width: 0, opacity: 0 }}
            animate={{ width: 400, opacity: 1 }}
            exit={{ width: 0, opacity: 0 }}
            transition={{ type: 'spring', damping: 28, stiffness: 200 }}
          >
            <div className="panel-inner">
              <div className="panel-header">
                <Activity size={18} />
                <h3>Privacy Audit</h3>
              </div>

              {lastBotMessage?.entities ? (
                <div className="panel-scroll">
                  <div className="m-card">
                    <label>Overhead</label>
                    <div className="val">
                      {lastBotMessage.metrics ? (lastBotMessage.metrics.regex_time_ms + lastBotMessage.metrics.ai_model_time_ms).toFixed(1) : '0'} ms
                    </div>
                  </div>

                  <div className="audit-section">
                    {lastBotMessage.entities.map((ent, i) => (
                      <div key={i} className="audit-card">
                        <span className="label-chip">{ent.type}</span>
                        <div className="data-flow">
                          <span className="masked">{ent.token}</span>
                          <ChevronRight size={10} />
                          <span className="unmasked">{ent.original}</span>
                        </div>
                      </div>
                    ))}
                  </div>

                  <div className="payload-section">
                    <pre className="code-view">{lastBotMessage.maskedText}</pre>
                  </div>
                </div>
              ) : (
                <div className="panel-empty" style={{ opacity: 0.2, textAlign: 'center', marginTop: '50%' }}>
                  <Info size={32} style={{ marginBottom: '1rem' }} />
                  <p>No active scan data.</p>
                </div>
              )}
            </div>
          </motion.aside>
        )}
      </AnimatePresence>
    </div>
  );
};

export default AXION;
