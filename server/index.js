const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

const express = require('express');
const https   = require('https');

const app  = express();
const PORT = process.env.PORT || 3000;

// Support Groq (preferred, free) or Gemini as fallback
const GROQ_KEY   = process.env.GROQ_API_KEY   || '';
const GEMINI_KEY = process.env.GEMINI_API_KEY  || '';
const HAS_KEY    = Boolean(GROQ_KEY || GEMINI_KEY);

app.use(express.json());

// ── Serve static files ────────────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, '..', 'public')));

// ── Config endpoint ───────────────────────────────────────────────────────────
app.get('/config', (_req, res) => {
  res.json({
    hasKey:   HAS_KEY,
    provider: GROQ_KEY ? 'groq' : GEMINI_KEY ? 'gemini' : 'none',
  });
});

// ── Helper: make HTTPS request ────────────────────────────────────────────────
function httpsPost(options, body) {
  return new Promise((resolve, reject) => {
    const req = https.request(options, r => {
      let data = '';
      r.on('data', c => (data += c));
      r.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch (e) { reject(new Error('Invalid JSON from API')); }
      });
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

// ── Groq provider (llama-3.3-70b) ────────────────────────────────────────────
async function callGroq(prompt) {
  const body = JSON.stringify({
    model:       'llama-3.3-70b-versatile',
    max_tokens:  2048,
    temperature: 0.4,
    messages: [{ role: 'user', content: prompt }],
  });
  const data = await httpsPost({
    hostname: 'api.groq.com',
    path:     '/openai/v1/chat/completions',
    method:   'POST',
    headers: {
      'Content-Type':   'application/json',
      'Content-Length': Buffer.byteLength(body),
      'Authorization':  `Bearer ${GROQ_KEY}`,
    },
  }, body);
  if (data.error) throw new Error(data.error.message || 'Groq error');
  return data.choices?.[0]?.message?.content || '';
}

// ── Gemini provider (fallback) ────────────────────────────────────────────────
async function callGemini(prompt) {
  const body = JSON.stringify({
    contents: [{ parts: [{ text: prompt }] }],
    generationConfig: { maxOutputTokens: 2048, temperature: 0.4 },
  });
  const data = await httpsPost({
    hostname: 'generativelanguage.googleapis.com',
    path:     `/v1beta/models/gemini-2.0-flash-lite:generateContent?key=${GEMINI_KEY}`,
    method:   'POST',
    headers: {
      'Content-Type':   'application/json',
      'Content-Length': Buffer.byteLength(body),
    },
  }, body);
  if (data.error) throw new Error(data.error.message || 'Gemini error');
  return data.candidates?.[0]?.content?.parts?.[0]?.text || '';
}

// ── Proxy endpoint ────────────────────────────────────────────────────────────
app.post('/api/analyze', async (req, res) => {
  const { prompt } = req.body;
  if (!prompt)  return res.status(400).json({ error: 'Missing prompt' });
  if (!HAS_KEY) return res.status(503).json({ error: 'No AI API key configured. Set GROQ_API_KEY or GEMINI_API_KEY in .env' });

  try {
    const text = GROQ_KEY ? await callGroq(prompt) : await callGemini(prompt);
    res.json({ text });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Start ─────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n⬡  Android Attack Surface Mapper`);
  console.log(`   http://localhost:${PORT}`);
  if (GROQ_KEY)        console.log('   Groq (llama-3.3-70b) — AI analysis enabled ✓\n');
  else if (GEMINI_KEY) console.log('   Gemini — AI analysis enabled ✓\n');
  else {
    console.log('\n   ⚠️  No AI key configured.');
    console.log('   Set GROQ_API_KEY=gsk_... in .env for free AI analysis\n');
  }
});
