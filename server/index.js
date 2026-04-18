/**
 * server/index.js — Express server
 *
 * - Serves the static frontend from /public
 * - Proxies AI requests to Anthropic so the API key never reaches the browser
 *
 * Usage:
 *   ANTHROPIC_API_KEY=sk-ant-... node server/index.js
 *   # or
 *   npm start
 */

const express = require('express');
const path    = require('path');
const https   = require('https');

const app  = express();
const PORT = process.env.PORT || 3000;
const KEY  = process.env.ANTHROPIC_API_KEY || '';

app.use(express.json());

// ── Serve static files ────────────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, '..', 'public')));

// ── Config endpoint (expose safe config to the browser) ───────────────────────
app.get('/config', (_req, res) => {
  res.json({
    hasKey: Boolean(KEY),
    // Never send the actual key — the proxy handles auth
  });
});

// ── Proxy endpoint ────────────────────────────────────────────────────────────
app.post('/api/analyze', (req, res) => {
  const { prompt } = req.body;
  if (!prompt) return res.status(400).json({ error: 'Missing prompt' });
  if (!KEY)    return res.status(503).json({ error: 'ANTHROPIC_API_KEY not set on the server' });

  const body = JSON.stringify({
    model: 'claude-sonnet-4-20250514',
    max_tokens: 1000,
    messages: [{ role: 'user', content: prompt }],
  });

  const options = {
    hostname: 'api.anthropic.com',
    path: '/v1/messages',
    method: 'POST',
    headers: {
      'Content-Type':      'application/json',
      'Content-Length':    Buffer.byteLength(body),
      'x-api-key':         KEY,
      'anthropic-version': '2023-06-01',
    },
  };

  const apiReq = https.request(options, apiRes => {
    let data = '';
    apiRes.on('data', chunk => (data += chunk));
    apiRes.on('end', () => {
      try {
        const parsed = JSON.parse(data);
        const text   = (parsed.content || []).map(b => b.text || '').join('');
        res.json({ text });
      } catch (e) {
        res.status(500).json({ error: 'Failed to parse Anthropic response' });
      }
    });
  });

  apiReq.on('error', err => res.status(500).json({ error: err.message }));
  apiReq.write(body);
  apiReq.end();
});

// ── Start ─────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n⬡  Android Attack Surface Mapper`);
  console.log(`   http://localhost:${PORT}`);
  if (!KEY) {
    console.log('\n   ⚠️  ANTHROPIC_API_KEY is not set.');
    console.log('   AI analysis will not work until you set it:\n');
    console.log('   export ANTHROPIC_API_KEY=sk-ant-...');
    console.log('   npm start\n');
  } else {
    console.log('   API key detected — AI analysis enabled ✓\n');
  }
});
