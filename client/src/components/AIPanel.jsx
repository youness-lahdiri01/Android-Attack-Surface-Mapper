import { useState, useEffect, useRef, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { X, Sparkles, AlertOctagon, RotateCcw, Bot, Send, User, Loader } from 'lucide-react'

const SEV_COLOR = { critical: '#ff3b5c', high: '#ff9500', medium: '#ffd60a', low: '#3fb950' }

/* ── Prompt builders ─────────────────────────────────────────────── */
function buildInitialPrompt(finding, scanState) {
  if (finding) {
    return `You are a cybersecurity assistant analyzing an Android app. Explain this finding like a security professional talking to a developer.

Package: ${scanState.parsed.pkg} | Risk: ${scanState.score}/100

FINDING [${finding.sev.toUpperCase()}]: ${finding.title}
Details: ${finding.body}

Respond in this format:

**Why This Is Risky**
2-3 sentences on the real-world attack scenario.

**Exploit Steps**
1. Step one
2. Step two
3. Step three

**How to Fix**
Specific, actionable code-level fix.

**Effort:** Low / Medium / High`
  }

  const exported = scanState.parsed.components.filter(c => c.inferredExported)
  return `You are a cybersecurity assistant. Analyze this Android app's attack surface like a senior pentester.

Package: ${scanState.parsed.pkg} | Risk Score: ${scanState.score}/100 | SDK: ${scanState.parsed.targetSdk || '?'}

TOP FINDINGS:
${scanState.findings.slice(0, 5).map((f, i) => `${i + 1}. [${f.sev.toUpperCase()}] ${f.title}`).join('\n')}

EXPORTED COMPONENTS (${exported.length}):
${exported.map(c => `• ${c.type} ${c.name.replace(/^.*\./, '')} ${c.perm ? '[protected]' : '[UNGUARDED]'}`).join('\n')}

PERMISSIONS: ${scanState.parsed.permissions.map(p => p.split('.').pop()).join(', ') || 'none'}

Respond in this format:

**Threat Narrative**
What can an attacker actually do?

**Top 3 Attack Vectors**
1. Vector one
2. Vector two
3. Vector three

**Verdict**
One sentence risk verdict.`
}

function buildFollowUpPrompt(userMessage, history, finding, scanState) {
  const ctx = finding
    ? `Finding: [${finding.sev.toUpperCase()}] ${finding.title}`
    : `App: ${scanState.parsed.pkg} (Risk: ${scanState.score}/100)`

  const historyText = history
    .filter(m => m.role !== 'system')
    .map(m => `${m.role === 'user' ? 'Developer' : 'Security Expert'}: ${m.content}`)
    .join('\n\n')

  return `You are a cybersecurity assistant. Context: ${ctx}

Previous conversation:
${historyText}

Developer: ${userMessage}

Respond as a concise security expert (2-4 sentences max). Use **bold** for key terms. Be direct and actionable.`
}

/* ── Typing indicator ────────────────────────────────────────────── */
function TypingIndicator() {
  return (
    <div className="flex items-center gap-1 px-2 py-1.5">
      {[0, 1, 2].map(i => (
        <motion.div
          key={i}
          className="w-1.5 h-1.5 rounded-full"
          style={{ background: '#a371f7' }}
          animate={{ y: [0, -4, 0], opacity: [0.4, 1, 0.4] }}
          transition={{ duration: 0.8, delay: i * 0.18, repeat: Infinity }}
        />
      ))}
    </div>
  )
}

/* ── Message bubble ──────────────────────────────────────────────── */
function MessageBubble({ msg, index }) {
  const isUser = msg.role === 'user'

  function formatContent(text) {
    return text
      .replace(/\*\*(.+?)\*\*/g, '<strong style="color:#00d4ff">$1</strong>')
      .replace(/\n\n/g, '</p><p style="margin-top:8px">')
      .replace(/\n(\d+)\.\s/g, '<br/><span style="color:#a371f7;font-weight:700;font-family:JetBrains Mono,monospace">$1.</span> ')
      .replace(/\n•\s/g, '<br/>• ')
      .replace(/\n/g, '<br/>')
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 12, scale: 0.97 }}
      animate={{ opacity: 1, y: 0, scale: 1 }}
      transition={{ delay: index * 0.04, type: 'spring', stiffness: 400, damping: 30 }}
      className={`flex gap-2 ${isUser ? 'flex-row-reverse' : 'flex-row'}`}
    >
      {/* Avatar */}
      <div
        className="flex-shrink-0 w-7 h-7 rounded-lg flex items-center justify-center self-end mb-1"
        style={{
          background: isUser ? 'rgba(88,166,255,0.15)' : 'rgba(163,113,247,0.15)',
          border: `1px solid ${isUser ? 'rgba(88,166,255,0.3)' : 'rgba(163,113,247,0.3)'}`,
        }}
      >
        {isUser ? <User size={12} className="text-neon-blue" /> : <Bot size={12} className="text-neon-purple" />}
      </div>

      {/* Bubble */}
      <div
        className={`max-w-[84%] rounded-xl px-3 py-2.5 text-[11px] font-mono leading-relaxed ${isUser ? 'rounded-br-sm' : 'rounded-bl-sm'}`}
        style={isUser
          ? { background: 'rgba(88,166,255,0.1)', border: '1px solid rgba(88,166,255,0.25)', color: '#c9d1d9' }
          : { background: 'rgba(22,27,34,0.9)', border: '1px solid rgba(255,255,255,0.07)', color: '#8b949e' }
        }
      >
        {msg.isError ? (
          <span className="text-neon-red">{msg.content}</span>
        ) : (
          <p dangerouslySetInnerHTML={{ __html: formatContent(msg.content) }} />
        )}
      </div>
    </motion.div>
  )
}

/* ── Main panel ──────────────────────────────────────────────────── */
export default function AIPanel({ finding, scanState, onClose }) {
  const [messages,  setMessages]  = useState([])
  const [input,     setInput]     = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const bottomRef = useRef(null)
  const inputRef  = useRef(null)

  const scrollToBottom = useCallback(() => {
    setTimeout(() => bottomRef.current?.scrollIntoView({ behavior: 'smooth' }), 50)
  }, [])

  const sendMessage = useCallback(async (userText, history) => {
    setIsLoading(true)
    try {
      const prompt = history.length === 0
        ? buildInitialPrompt(finding, scanState)
        : buildFollowUpPrompt(userText, history, finding, scanState)

      const r = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ prompt }),
      })
      const json = await r.json()
      if (!r.ok) throw new Error(json.error || 'API error')

      setMessages(prev => [...prev, { role: 'assistant', content: json.text || '' }])
    } catch (err) {
      setMessages(prev => [...prev, { role: 'assistant', content: `Error: ${err.message}`, isError: true }])
    } finally {
      setIsLoading(false)
    }
  }, [finding, scanState])

  // Auto-load initial analysis when panel opens
  useEffect(() => {
    setMessages([])
    setInput('')
    sendMessage(null, [])
  }, [finding])

  useEffect(() => { scrollToBottom() }, [messages, isLoading])

  const handleSend = useCallback(async () => {
    const text = input.trim()
    if (!text || isLoading) return

    const userMsg = { role: 'user', content: text }
    const newHistory = [...messages, userMsg]
    setMessages(newHistory)
    setInput('')
    scrollToBottom()

    await sendMessage(text, newHistory)
  }, [input, isLoading, messages, sendMessage, scrollToBottom])

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); handleSend() }
  }

  const SUGGESTED = finding
    ? ['How would an attacker exploit this?', 'Show me a fix in Kotlin', 'How severe is this really?']
    : ['What is the biggest risk?', 'How do I fix the exported components?', 'Summarize in one sentence']

  return (
    <motion.div
      initial={{ x: '100%', opacity: 0 }}
      animate={{ x: 0, opacity: 1 }}
      exit={{ x: '100%', opacity: 0 }}
      transition={{ type: 'spring', stiffness: 320, damping: 32 }}
      className="fixed right-0 top-0 bottom-0 w-[440px] z-50 flex flex-col"
      style={{ background: '#0d1117', borderLeft: '1px solid rgba(255,255,255,0.08)', boxShadow: '-12px 0 48px rgba(0,0,0,0.5)' }}
    >
      {/* Header */}
      <div
        className="flex items-center gap-3 px-4 py-3 flex-shrink-0"
        style={{ borderBottom: '1px solid rgba(255,255,255,0.07)', background: 'rgba(22,27,34,0.9)' }}
      >
        <div className="w-8 h-8 rounded-xl flex items-center justify-center flex-shrink-0"
          style={{ background: 'rgba(163,113,247,0.15)', border: '1px solid rgba(163,113,247,0.35)', boxShadow: '0 0 16px rgba(163,113,247,0.2)' }}>
          <Sparkles size={15} className="text-neon-purple" />
        </div>
        <div className="flex-1 min-w-0">
          <div className="text-xs font-mono font-bold text-t1">AI Security Assistant</div>
          <div className="text-[9px] font-mono text-t3 truncate">
            {finding ? finding.title : `Analyzing ${scanState.parsed.pkg}`}
          </div>
        </div>
        <button
          onClick={onClose}
          className="p-1.5 rounded-lg text-t3 hover:text-t1 glass-light border border-b1 transition-colors flex-shrink-0"
        >
          <X size={13} />
        </button>
      </div>

      {/* Context badge */}
      {finding && (
        <div
          className="mx-4 mt-3 p-2.5 rounded-lg flex items-center gap-2 flex-shrink-0"
          style={{ background: (SEV_COLOR[finding.sev] || '#58a6ff') + '0c', border: `1px solid ${SEV_COLOR[finding.sev] || '#58a6ff'}25` }}
        >
          <AlertOctagon size={10} style={{ color: SEV_COLOR[finding.sev], flexShrink: 0 }} />
          <span className="text-[9px] font-mono font-bold tracking-widest flex-shrink-0"
            style={{ color: SEV_COLOR[finding.sev] }}>
            {finding.sev.toUpperCase()}
          </span>
          <span className="text-[10px] font-mono text-t2 truncate">{finding.title}</span>
        </div>
      )}

      {/* Messages */}
      <div className="flex-1 overflow-y-auto px-4 py-3 flex flex-col gap-3">
        <AnimatePresence>
          {messages.map((msg, i) => (
            <MessageBubble key={i} msg={msg} index={i} />
          ))}
        </AnimatePresence>

        {isLoading && (
          <motion.div
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            className="flex gap-2 items-end"
          >
            <div className="w-7 h-7 rounded-lg flex items-center justify-center flex-shrink-0"
              style={{ background: 'rgba(163,113,247,0.15)', border: '1px solid rgba(163,113,247,0.3)' }}>
              <Bot size={12} className="text-neon-purple" />
            </div>
            <div className="px-3 py-2 rounded-xl rounded-bl-sm"
              style={{ background: 'rgba(22,27,34,0.9)', border: '1px solid rgba(255,255,255,0.07)' }}>
              <TypingIndicator />
            </div>
          </motion.div>
        )}

        <div ref={bottomRef} />
      </div>

      {/* Suggested questions (only when no conversation yet after initial) */}
      {messages.length === 1 && !isLoading && (
        <div className="px-4 pb-2 flex flex-col gap-1.5 flex-shrink-0">
          <div className="text-[9px] font-mono text-t3 tracking-widest mb-0.5">SUGGESTED QUESTIONS</div>
          {SUGGESTED.map(q => (
            <button
              key={q}
              onClick={() => { setInput(q); setTimeout(() => inputRef.current?.focus(), 0) }}
              className="text-left text-[10px] font-mono text-t2 hover:text-neon-cyan px-3 py-2 rounded-lg transition-all duration-150"
              style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.05)' }}
            >
              <span className="text-t3 mr-1">↳</span>{q}
            </button>
          ))}
        </div>
      )}

      {/* Input bar */}
      <div
        className="px-4 py-3 flex-shrink-0 flex items-end gap-2"
        style={{ borderTop: '1px solid rgba(255,255,255,0.07)', background: 'rgba(13,17,23,0.95)' }}
      >
        <div
          className="flex-1 flex items-end gap-2 rounded-xl px-3 py-2.5"
          style={{ background: 'rgba(33,38,45,0.8)', border: '1px solid rgba(255,255,255,0.08)' }}
        >
          <textarea
            ref={inputRef}
            value={input}
            onChange={e => setInput(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Ask about this vulnerability…"
            rows={1}
            className="flex-1 bg-transparent text-[11px] font-mono text-t1 placeholder-t3 outline-none resize-none leading-relaxed"
            style={{ maxHeight: '80px' }}
          />
        </div>
        <button
          onClick={handleSend}
          disabled={!input.trim() || isLoading}
          className="flex-shrink-0 w-9 h-9 rounded-xl flex items-center justify-center transition-all duration-150 disabled:opacity-30"
          style={{
            background: input.trim() && !isLoading ? 'rgba(163,113,247,0.2)' : 'rgba(255,255,255,0.05)',
            border: `1px solid ${input.trim() && !isLoading ? 'rgba(163,113,247,0.5)' : 'rgba(255,255,255,0.08)'}`,
            boxShadow: input.trim() && !isLoading ? '0 0 12px rgba(163,113,247,0.2)' : 'none',
          }}
        >
          {isLoading
            ? <Loader size={13} className="text-neon-purple animate-spin" />
            : <Send size={13} style={{ color: input.trim() ? '#a371f7' : '#6e7681' }} />
          }
        </button>
      </div>
    </motion.div>
  )
}
