import React, { useState, useEffect, useRef } from 'react';
import {
  Sparkles,
  Send,
  Bot,
  User,
  ShieldCheck,
  AlertCircle,
  HelpCircle,
  Loader2,
  Cpu,
} from 'lucide-react';
import { copilotApi } from '../api/copilotApi';
import MarkdownRenderer from './MarkdownRenderer';

export default function CopilotChat({ analysis }) {
  const [messages, setMessages] = useState([]);
  const [inputMessage, setInputMessage] = useState('');
  const [loading, setLoading] = useState(false);
  const [status, setStatus] = useState({ online: true, model: 'mailscope-sec:3b' });
  const [suggestions, setSuggestions] = useState([]);
  const [loadingSuggestions, setLoadingSuggestions] = useState(true);
  const [error, setError] = useState(null);

  const messagesEndRef = useRef(null);
  const inputRef = useRef(null);

  const analysisId = analysis?.analysis_id;
  const filename = analysis?.filename || 'packet_capture.pcap';
  const findingsCount = analysis?.findings?.length || 0;
  const sessionCount = analysis?.sessions?.length || 0;

  // Auto-scroll to bottom of conversation
  const scrollToBottom = () => {
    if (typeof messagesEndRef.current?.scrollIntoView === 'function') {
      messagesEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages, loading]);

  // Initial load: fetch status, suggestions, and set welcome greeting
  useEffect(() => {
    let isMounted = true;

    async function initializeCopilot() {
      // 1. Check status
      try {
        const statusRes = await copilotApi.getStatus();
        if (isMounted) {
          setStatus({
            online: statusRes.status === 'online',
            model: statusRes.model || 'mailscope-sec:3b',
          });
        }
      } catch {
        if (isMounted) {
          setStatus({ online: false, model: 'mailscope-sec:3b' });
        }
      }

      // 2. Fetch context-aware suggested questions
      try {
        setLoadingSuggestions(true);
        const fetchedSuggestions = await copilotApi.getSuggestions(analysisId, analysis);
        if (isMounted) {
          setSuggestions(fetchedSuggestions);
        }
      } catch {
        if (isMounted) {
          setSuggestions([]);
        }
      } finally {
        if (isMounted) {
          setLoadingSuggestions(false);
        }
      }

      // 3. Setup initial welcome message
      if (isMounted) {
        const welcomeMsg = {
          id: 'welcome',
          role: 'assistant',
          content: `Hello! I am your **Agent SMS** specialized in email traffic inspection. I have reviewed **${filename}** (${sessionCount} session${sessionCount !== 1 ? 's' : ''}, ${findingsCount} finding${findingsCount !== 1 ? 's' : ''}). \n\nYou can click any suggested question below or type your own question to inspect security findings, protocol risks, or remediation guidelines.`,
          source: 'ollama',
          model: 'mailscope-sec:3b',
          timestamp: new Date(),
        };

        setMessages((prev) => (prev.some((m) => m.id === 'welcome') ? prev : [welcomeMsg, ...prev]));
      }
    }

    initializeCopilot();

    return () => {
      isMounted = false;
    };
  }, [analysisId, filename, findingsCount, sessionCount]);

  // Send a message
  const handleSendMessage = async (textToSend) => {
    const query = (textToSend || inputMessage).trim();
    if (!query || loading) return;

    setError(null);
    setInputMessage('');

    // Append user message to thread
    const userMsg = {
      id: `user-${Date.now()}`,
      role: 'user',
      content: query,
      timestamp: new Date(),
    };

    const newHistory = [...messages, userMsg];
    setMessages(newHistory);
    setLoading(true);

    try {
      // Build conversation history for API (omit greeting if desired, format {role, content})
      const apiHistory = newHistory
        .filter((m) => m.id !== 'welcome')
        .map((m) => ({
          role: m.role,
          content: m.content,
        }));

      const result = await copilotApi.chat({
        message: query,
        analysisId: analysisId || 'demo-capture',
        history: apiHistory.slice(0, -1), // prior turns
      });

      const assistantMsg = {
        id: `assistant-${Date.now()}`,
        role: 'assistant',
        content: result.response,
        model: result.model || status.model,
        source: result.source || 'ollama',
        timestamp: new Date(),
      };

      setMessages((prev) => [...prev, assistantMsg]);
    } catch (err) {
      setError(
        err.message ||
          'Failed to connect to the AI copilot. Please check that Ollama is running.'
      );
    } finally {
      setLoading(false);
      setTimeout(() => inputRef.current?.focus(), 100);
    }
  };

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSendMessage();
    }
  };

  return (
    <div className="flex h-[750px] flex-col overflow-hidden rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 shadow-sm">
      {/* =========================================================
          CHAT HEADER
      ========================================================== */}
      <div className="flex flex-wrap items-center justify-between border-b border-slate-100 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-850/80 px-5 py-3.5">
        <div className="flex items-center gap-3">
          <div className="flex h-7 w-7 shrink-0 items-center justify-center overflow-hidden rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 shadow-sm">
            <img
              src="/Agent_SMS_logo.jpeg"
              alt="Agent SMS"
              className="h-full w-full object-contain p-0.5"
            />
          </div>

          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-sm font-bold text-slate-800 dark:text-white">
                Agent SMS
              </h2>
              <span className="rounded-md border border-brand-200 dark:border-brand-800 bg-brand-50 dark:bg-brand-950/60 px-2 py-0.5 text-[10px] font-semibold text-brand-700 dark:text-brand-300">
                OLLAMA
              </span>
            </div>
            <p className="text-[11px] text-slate-500 dark:text-slate-400">
              Grounded in active capture:{' '}
              <span className="font-mono font-medium text-slate-700 dark:text-slate-200">
                {filename}
              </span>
            </p>
          </div>
        </div>

        {/* Status Pill */}
        <div className="flex items-center gap-2">
          <div
            className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[11px] font-medium ${
              status.online
                ? 'border-emerald-200 dark:border-emerald-800/60 bg-emerald-50 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-300'
                : 'border-amber-200 dark:border-amber-800/60 bg-amber-50 dark:bg-amber-950/40 text-amber-700 dark:text-amber-300'
            }`}
          >
            <span
              className={`h-2 w-2 rounded-full ${
                status.online ? 'bg-emerald-500 animate-pulse' : 'bg-amber-500'
              }`}
            />
            <Cpu className="h-3 w-3" />
            <span>{status.model}</span>
            <span>·</span>
            <span>{status.online ? 'Online' : 'Offline'}</span>
          </div>
        </div>
      </div>

      {/* =========================================================
          MESSAGES THREAD
      ========================================================== */}
      <div className="flex-1 overflow-y-auto p-4 sm:p-6 space-y-4">
        {messages.map((msg) => {
          const isUser = msg.role === 'user';

          return (
            <div
              key={msg.id}
              className={`flex gap-3 ${isUser ? 'justify-end' : 'justify-start'}`}
            >
              {!isUser && (
                <div className="flex h-7 w-7 shrink-0 items-center justify-center overflow-hidden rounded-full border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 shadow-sm mt-0.5">
                  <img
                    src="/Agent_SMS_logo.jpeg"
                    alt="Agent SMS"
                    className="h-full w-full object-contain p-0.5"
                  />
                </div>
              )}

              <div className={`max-w-[85%] sm:max-w-[75%]`}>
                <div
                  className={`rounded-2xl px-4 py-3 text-xs sm:text-sm leading-relaxed ${
                    isUser
                      ? 'rounded-br-sm bg-brand-600 text-white shadow-sm'
                      : 'rounded-tl-sm border border-slate-200/80 dark:border-slate-800 bg-slate-50/60 dark:bg-slate-800/80 text-slate-800 dark:text-slate-100'
                  }`}
                >
                  {isUser ? (
                    <div className="whitespace-pre-wrap font-sans">
                      {msg.content}
                    </div>
                  ) : (
                    <MarkdownRenderer content={msg.content} />
                  )}
                </div>

                {/* Assistant Metadata: model & source */}
                {!isUser && (msg.source || msg.model) && (
                  <div className="mt-1.5 flex items-center gap-2 px-1 text-[10px] text-slate-400 dark:text-slate-500">
                    <span className="flex items-center gap-1 font-mono">
                      <Cpu className="h-3 w-3" />
                      {msg.model || status.model}
                    </span>
                    <span>·</span>
                    <span>source: {msg.source || 'ollama'}</span>
                  </div>
                )}
              </div>

              {isUser && (
                <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-slate-800 text-white shadow-sm mt-0.5">
                  <User className="h-3.5 w-3.5" />
                </div>
              )}
            </div>
          );
        })}

        {/* Loading / Generating State */}
        {loading && (
          <div className="flex gap-3 justify-start">
            <div className="flex h-7 w-7 shrink-0 items-center justify-center overflow-hidden rounded-full border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 shadow-sm mt-0.5">
              <img
                src="/Agent_SMS_logo.jpeg"
                alt="Agent SMS"
                className="h-full w-full object-contain p-0.5"
              />
            </div>

            <div className="rounded-2xl rounded-tl-sm border border-slate-200 dark:border-slate-800 bg-slate-50/80 dark:bg-slate-800 px-4 py-3 text-slate-700 dark:text-slate-200 shadow-sm">
              <div className="flex items-center gap-2 text-xs font-medium text-slate-600 dark:text-slate-300">
                <Loader2 className="h-3.5 w-3.5 animate-spin text-brand-600 dark:text-brand-400" />
                <span>Thinking & inspecting packet context with {status.model}...</span>
              </div>
            </div>
          </div>
        )}

        {/* Error Banner */}
        {error && (
          <div className="rounded-xl border border-rose-200 dark:border-rose-900/60 bg-rose-50/80 dark:bg-rose-950/40 p-3 text-xs text-rose-700 dark:text-rose-300 flex items-center gap-2">
            <AlertCircle className="h-4 w-4 shrink-0 text-rose-500" />
            <span className="flex-1">{error}</span>
          </div>
        )}

        <div ref={messagesEndRef} />
      </div>

      {/* =========================================================
          SUGGESTED QUESTIONS (Quick-Prompts)
      ========================================================== */}
      {suggestions.length > 0 && (
        <div className="border-t border-slate-100 dark:border-slate-800 bg-slate-50/40 dark:bg-slate-950/40 px-4 py-2.5">
          <div className="flex items-center gap-1.5 mb-2 text-[11px] font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">
            <HelpCircle className="h-3 w-3 text-brand-500" />
            <span>Suggested Questions</span>
          </div>

          <div className="flex flex-wrap gap-2">
            {suggestions.map((q, idx) => (
              <button
                key={idx}
                type="button"
                disabled={loading}
                onClick={() => handleSendMessage(q)}
                className="
                  rounded-lg border border-slate-200 dark:border-slate-700
                  bg-white dark:bg-slate-800
                  px-2.5 py-1.5 text-left text-[11px] font-medium
                  text-slate-700 dark:text-slate-300
                  transition-all duration-150
                  hover:border-brand-300 dark:hover:border-brand-500/60
                  hover:bg-brand-50/50 dark:hover:bg-brand-950/60
                  hover:text-brand-700 dark:hover:text-brand-300
                  active:scale-[0.99]
                  disabled:opacity-50 disabled:cursor-not-allowed
                "
              >
                {q}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* =========================================================
          INPUT BAR
      ========================================================== */}
      <div className="border-t border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-3 sm:p-4">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleSendMessage();
          }}
          className="flex items-center gap-2"
        >
          <input
            ref={inputRef}
            type="text"
            value={inputMessage}
            onChange={(e) => setInputMessage(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Ask about security findings, TLS configurations, remediation steps..."
            disabled={loading}
            className="
              flex-1 rounded-xl border border-slate-200 dark:border-slate-700
              bg-slate-50/60 dark:bg-slate-800/80 px-4 py-2.5
              text-xs sm:text-sm text-slate-800 dark:text-slate-100
              placeholder-slate-400 dark:placeholder-slate-500
              transition-colors
              focus:border-brand-500 focus:bg-white dark:focus:bg-slate-800 focus:outline-none focus:ring-2 focus:ring-brand-500/10
              disabled:opacity-60
            "
          />

          <button
            type="submit"
            disabled={!inputMessage.trim() || loading}
            className="
              inline-flex h-10 w-10 items-center justify-center
              rounded-xl bg-brand-600 text-white
              transition-all
              hover:bg-brand-700
              active:scale-95
              disabled:opacity-40 disabled:cursor-not-allowed disabled:hover:bg-brand-600
            "
            title="Send message"
          >
            <Send className="h-4 w-4" />
          </button>
        </form>

        <div className="mt-2 flex items-center justify-between px-1 text-[10px] text-slate-400 dark:text-slate-500">
          <span>Press <strong>Enter</strong> to send</span>
          <span className="flex items-center gap-1">
            <ShieldCheck className="h-3 w-3 text-emerald-500" />
            Hardware isolated & local Ollama execution
          </span>
        </div>
      </div>
    </div>
  );
}
