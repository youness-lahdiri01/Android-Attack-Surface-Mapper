# Android Attack Surface Mapper

## Overview

Android Attack Surface Mapper (AASM) is a security analysis tool for auditing Android applications by analyzing APK files or `AndroidManifest.xml` directly in the browser.

All analysis runs locally — no data leaves the machine, no API keys are required for core functionality.

## Features

- Upload and analyze APK files or raw `AndroidManifest.xml`
- Automatic extraction of `AndroidManifest.xml` from APK
- Static security analysis with weighted risk scoring (0–100)
- Attack surface graph (D3.js, interactive, zoom/pan)
- Risk gauge dashboard with contextual threat narrative
- Findings grid with severity badges, inline remediation, and hover glossary tooltips
- Component browser sidebar (filter by type, search, per-component risk dots)
- AI-powered deep analysis per finding or full-app threat narrative (optional)
- Export results as JSON, CSV, or Mermaid diagram
- Filter findings by severity (critical / high / medium / low)
- Demo mode — try it without uploading an APK
- Dark/light theme toggle

## Detected Vulnerabilities

- Debuggable application in production
- ADB backup enabled (`allowBackup`)
- Cleartext HTTP traffic allowed
- Low `targetSdkVersion` (API < 31 flagged, API < 23 as high severity)
- Exported components without a permission guard
- Exposed `ContentProvider` without `readPermission`/`writePermission`
- Deep links without `autoVerify` (URL hijacking risk)
- Dangerous permissions declared
- Implicitly exported components via intent-filter (pre-API 31 behavior)
- Custom `taskAffinity` on exported activities (task hijacking)

## Risk Score

| Score | Level |
|-------|-------|
| 0–29  | Low |
| 30–59 | Medium |
| 60–79 | High Risk |
| 80–100 | Critical |

## AI Analysis (optional)

The AI panel provides per-finding or full-app analysis powered by a configurable LLM backend. Supported providers (set one key in `.env`):

| Provider | Model | Key |
|----------|-------|-----|
| Groq (default) | `llama-3.3-70b-versatile` | `GROQ_API_KEY` |
| Gemini (fallback) | `gemini-2.0-flash-lite` | `GEMINI_API_KEY` |

Each analysis includes: real-world attack scenario, step-by-step exploit walkthrough, actionable code-level fix, and effort estimate. The panel also supports follow-up questions via chat.

## Installation

Clone the repository:

```
git clone https://github.com/youness-lahdiri01/Android-Attack-Surface-Mapper.git
cd Android-Attack-Surface-Mapper
```

Install dependencies:

```
npm install
```

(Optional) Configure AI analysis — copy `.env.example` to `.env` and add a key:

```
GROQ_API_KEY=gsk_...
```

Build the React frontend:

```
cd client && npm install && npm run build && cd ..
```

Start the server:

```
npm start
```

## Usage

Open a browser and go to:

```
http://localhost:3000
```

Drop an APK file onto the upload zone. The tool extracts the manifest, runs all security checks, computes the risk score, and renders the attack graph, findings, and component list. Click **Try Demo** to run against a built-in sample without uploading anything.

## Project Structure

```
android-attack-surface-mapper/
│
├── client/                        # React + Vite frontend (v2 UI)
│   └── src/
│       ├── components/
│       │   ├── AIPanel.jsx        # AI analysis panel with chat
│       │   ├── AttackGraph.jsx    # D3.js interactive attack graph
│       │   ├── DropZone.jsx       # Drag-and-drop APK uploader
│       │   ├── FindingsGrid.jsx   # Severity-sorted findings with glossary tooltips
│       │   ├── Header.jsx         # Package info, risk badge, export buttons
│       │   ├── RiskGauge.jsx      # Animated SVG risk gauge dashboard
│       │   └── Sidebar.jsx        # Component browser with search and risk dots
│       ├── hooks/
│       │   └── useTheme.js
│       └── lib/
│           ├── apk.js             # APK loader and manifest extractor
│           ├── axml.js            # Binary Android XML decoder
│           ├── findings.js        # Security checks engine
│           └── parser.js          # Manifest parser
│
├── public/                        # Legacy plain-JS frontend (fallback)
│   ├── axml.js
│   ├── apk.js
│   ├── parser.js
│   ├── findings.js
│   ├── graph.js
│   └── app.js
│
├── server/
│   └── index.js                   # Express server + AI proxy endpoint
│
├── .env.example                   # API key template
└── package.json
```

## Security

The tool operates entirely locally. APK files are processed in the browser using the File API — nothing is uploaded to a server. The optional AI proxy only sends the analysis prompt (no raw APK data) to the configured provider.

## Screenshots

### Upload

Drop an APK or paste a manifest.

<img width="1307" height="886" alt="Screenshot 2026-04-18 205736" src="https://github.com/user-attachments/assets/63a73317-5b41-4f6c-93d3-61cec9d41332" />

### Findings

<img width="1356" height="871" alt="Screenshot 2026-04-18 205750" src="https://github.com/user-attachments/assets/dc17641e-74ce-415a-863d-ed4f1a7fb675" />

### Attack Surface Graph

<img width="1158" height="439" alt="Screenshot 2026-04-18 205652" src="https://github.com/user-attachments/assets/706a6a75-21f0-40c9-954a-d62e5c958311" />

### Security Report

<img width="1307" height="886" alt="Screenshot 2026-04-18 205736" src="https://github.com/user-attachments/assets/ef3d808d-7a00-43fa-a1ad-bd2d6c673a3a" />

## Future Improvements

- AAB file support
- Dynamic analysis
- CI/CD integration (GitHub Actions, GitLab CI)
- Certificate pinning detection
- Native library analysis

## Authors

Youness Lahdiri  
Amine KABBAJ
