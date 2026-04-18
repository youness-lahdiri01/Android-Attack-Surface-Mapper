# ⬡ Android Attack Surface Mapper

Audit Android apps by pasting their `AndroidManifest.xml`. The tool extracts all components, detects risky patterns, generates an attack graph, and runs an AI-powered security analysis.

![screenshot](https://via.placeholder.com/900x500/0e0e0f/e8e6e0?text=Android+Attack+Surface+Mapper)

## Features

| Feature | Details |
|---------|---------|
| **Component extraction** | Activities, Services, Receivers, Providers |
| **Risk detection** | Exported without permission, debuggable, allowBackup, deep links, overprivileged permissions |
| **Attack graph** | SVG graph of components ↔ intents ↔ permissions + Mermaid source |
| **Surface risk score** | 0–100 score based on exposure, privileges, and data access |
| **AI analysis** | Claude generates attack scenarios and a remediation roadmap |

## Quick start

### Option A — Static HTML (no server, no AI)

Open `public/index.html` directly in your browser. All parsing and graph features work. AI analysis requires an API key and a server.

### Option B — Express server (recommended, AI enabled)

**Prerequisites:** Node.js ≥ 16

```bash
# 1. Clone
git clone https://github.com/YOUR_USERNAME/android-attack-surface-mapper.git
cd android-attack-surface-mapper

# 2. Install dependencies
npm install

# 3. Set your Anthropic API key
cp .env.example .env
# Edit .env and paste your key from https://console.anthropic.com

# 4. Start
npm start
# → http://localhost:3000
```

> **Dev mode** (auto-restart on file changes):
> ```bash
> npm run dev
> ```

## Usage

1. Paste your `AndroidManifest.xml` into the input field (or click **Load demo manifest**)
2. Click **Scan manifest**
3. Navigate through the tabs:
   - **COMPONENTS** — full component table with risk indicators
   - **FINDINGS** — security findings sorted by severity
   - **GRAPH** — visual attack graph + Mermaid source
   - **AI ANALYSIS** — Claude's assessment and remediation roadmap

## Security checks performed

### App-level
- `android:debuggable="true"` in production
- `android:allowBackup="true"` (ADB data extraction)
- `android:usesCleartextTraffic="true"` (HTTP allowed)

### Component-level
- Exported components without permission guard
- ContentProviders exported without read/writePermission
- Deep links without `android:autoVerify="true"` (URL hijacking)
- Components implicitly exported via intent-filter (API < 31 risk)

### Permission-level
- Dangerous permissions (SMS, Contacts, Camera, Location, Storage…)

## Project structure

```
android-attack-surface-mapper/
├── public/
│   ├── index.html      # Main UI
│   ├── style.css       # Styles (dark/light mode)
│   ├── parser.js       # Manifest XML parser
│   ├── findings.js     # Security pattern detection
│   ├── graph.js        # SVG + Mermaid graph builder
│   ├── api.js          # Anthropic API client
│   └── app.js          # Main controller
├── server/
│   └── index.js        # Express server + API proxy
├── .env.example        # Environment variable template
├── .gitignore
└── package.json
```

## Environment variables

| Variable | Required | Description |
|----------|----------|-------------|
| `ANTHROPIC_API_KEY` | Yes (for AI) | Your key from [console.anthropic.com](https://console.anthropic.com) |
| `PORT` | No | Server port (default: 3000) |

## Chapters & labs covered

- Chapter 2 — Android component model
- Chapter 11 — IPC & intent security
- Chapter 12 — Defensive audit
- Lab 4, Lab 7 — Exported component audit

## License

MIT
