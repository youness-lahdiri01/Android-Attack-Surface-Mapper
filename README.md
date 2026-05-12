# Android Attack Surface Mapper

**v2.0.0 · MIT License · Browser-based · Zero install**

> A client-side static security analysis platform for Android applications — parse APKs, enumerate exposed components, visualize attack surfaces, and get AI-assisted remediation, all without leaving your browser.

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-v2.0.0-blue.svg)](https://github.com/youness-lahdiri01/Android-Attack-Surface-Mapper)
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.20090644.svg)](https://doi.org/10.5281/zenodo.20090644)
[![Tests](https://img.shields.io/badge/tests-20%20passing-brightgreen.svg)](#testing)
[![F1 Score](https://img.shields.io/badge/F1--Score-0.947-orange.svg)](#benchmark-results)

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Detection Rules](#detection-rules)
- [Risk Scoring](#risk-scoring)
- [Getting Started](#getting-started)
- [Usage](#usage)
- [AI-Assisted Remediation (Layer 4)](#ai-assisted-remediation-layer-4)
- [Benchmark Results](#benchmark-results)
- [Testing](#testing)
- [Limitations](#limitations)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [Citation](#citation)
- [License](#license)

---

## Overview

Android Attack Surface Mapper is an open-source, browser-based platform for **manifest-level static security analysis** of Android applications. It requires no installation, no server, and no Python environment — just open `index.html` in a modern browser and upload an APK.

The tool implements a **four-layer pipeline**:

| Layer | Description | Network? |
|-------|-------------|----------|
| 1 — APK Parsing | Extracts and decodes `AndroidManifest.xml` from APK (binary AXML format) | None |
| 2 — Rule Engine | Applies 10 deterministic security rules mapped to OWASP MSTG | None |
| 3 — Visualization & Report | Interactive D3.js attack graph + risk score + PDF/text export | None |
| 4 — AI Remediation *(optional)* | Context-aware fixes via Anthropic Claude API | HTTPS (optional) |

Layers 1–3 are **fully local and privacy-preserving** — no APK data ever leaves your machine. Layer 4 is opt-in and transmits only structured finding metadata (component name, misconfiguration type, package name, target SDK), never the APK binary.

---
<img width="1600" height="820" alt="WhatsApp Image 2026-05-08 at 18 43 31" src="https://github.com/user-attachments/assets/657b20a9-731d-4dcc-84bd-10eae6468856" />

## Features

- **Zero-install analysis** — open `index.html` in Chrome ≥ 90 or Firefox ≥ 88, no dependencies
- **Full APK support** — drag-and-drop APK files or paste raw `AndroidManifest.xml`
- **10 detection rules** aligned to OWASP MSTG v1.5.0 (PLATFORM-1 through PLATFORM-5, STORAGE-8, NETWORK-2, RESILIENCE-2)
- **Interactive attack graph** — D3.js force-directed visualization with color-coded component types and edge semantics
- **Quantitative risk score** — `[0, 100]` score with CVSS v3.1-aligned severity weights
- **Exportable reports** — PDF and plain-text remediation reports
- **AI-assisted remediation** — ready-to-paste XML manifest patches per finding (requires Anthropic API key)
- **Extensible rule engine** — add custom rules as plain JavaScript objects via `rule_schema.js`
- **Reproducible benchmark** — 10 annotated APK samples, ground-truth labels, SHA-256 checksums

---

## Architecture

```
┌────────────────────────────────────────────────────────┐
│                    Browser (client-side)                │
│                                                        │
│  ┌──────────────┐   ┌──────────────┐   ┌───────────┐  │
│  │   Layer 1    │──▶│   Layer 2    │──▶│  Layer 3  │  │
│  │ APK Parsing  │   │ Rule Engine  │   │  Viz &    │  │
│  │ AXML Decoder │   │ (10 rules)   │   │  Report   │  │
│  └──────────────┘   └──────────────┘   └───────────┘  │
│                                              │         │
└──────────────────────────────────────────────┼─────────┘
                                               │ (optional)
                                    ┌──────────▼──────────┐
                                    │      Layer 4         │
                                    │  Anthropic Claude    │
                                    │  API (HTTPS only)    │
                                    │  finding metadata    │
                                    │  only — no APK data  │
                                    └─────────────────────┘
```

**Repository structure:**

```
Android-Attack-Surface-Mapper/
├── index.html                  # Entry point (open directly in browser)
├── config.js                   # API key configuration (Layer 4)
├── src/
│   ├── parser/                 # AXML decoder + APK extractor (JSZip)
│   ├── rules/                  # Rule engine + rule_schema.js interface
│   │   └── dangerous_permissions.js
│   ├── visualization/          # D3.js attack graph module
│   └── report/                 # PDF / plain-text export
├── scoring/
│   └── weights.json            # Configurable severity weights
├── test/
│   └── rules.test.js           # 20 unit tests (2 per rule)
├── benchmark/
│   ├── run_benchmark.js        # Reproduces Table 5 results
│   ├── generate_synthetic.js   # Generates synthetic APK samples
│   ├── ground_truth.json       # Ground-truth labels
│   └── README.md               # Benchmark dataset description
└── CHECKSUMS.md                # SHA-256 checksums for all APK samples
```

---

## Detection Rules

All rules are evaluated against the parsed `AndroidManifest.xml` DOM. No bytecode or runtime analysis is performed.

| Rule | Severity | Detection Condition | MSTG Control |
|------|----------|---------------------|--------------|
| Exported Activity | **Critical** | `<activity exported="true">` with no `android:permission` | PLATFORM-1 |
| Exported Service | **High** | `<service exported="true">` with no `android:permission` | PLATFORM-2 |
| Exported Receiver | **High** | `<receiver exported="true">` with no `android:permission` | PLATFORM-3 |
| Exported Provider | **Critical** | `<provider exported="true" grantUriPermissions="true">` without both `readPermission` and `writePermission` | PLATFORM-1 |
| Debuggable Flag | **Critical** | `<application android:debuggable="true">` | RESILIENCE-2 |
| Backup Enabled | **Medium** | `<application android:allowBackup="true">` (default before API 31) | STORAGE-8 |
| Cleartext Traffic | **High** | `<application usesCleartextTraffic="true">` | NETWORK-2 |
| Implicit Broadcast | **Medium** | `<receiver exported="true">` with `<intent-filter>` but no `android:permission` | PLATFORM-3 |
| Dangerous Permission | **Medium** | Declares sensitive permissions (e.g. `READ_CONTACTS`, `ACCESS_FINE_LOCATION`, `READ_SMS`) | PLATFORM-1 |
| Low Target SDK | **Medium** | `targetSdkVersion < 28` (Android 9.0) | PLATFORM-1 |

**Adding custom rules:** implement the `rule_schema.js` interface and drop your rule object into `src/rules/` — no core module changes required.

**Known false positive/negative risks:**
- *Exported Activity* may produce false positives for activities intentionally exposed to partner apps via custom permissions (not currently evaluated).
- *Exported Provider* may miss providers whose `exported` attribute is set programmatically at runtime (accounts for the single false negative in the benchmark).

---

## Risk Scoring

The risk score **R ∈ [0, 100]** is computed as:

```
R = min(100, Σ wᵢ · cᵢ)
```

where `cᵢ` is the count of findings of severity `i` and `wᵢ` is the severity weight:

| Severity | Weight | CVSS v3.1 Range |
|----------|--------|-----------------|
| Critical | 25 | ≥ 9.0 |
| High | 15 | 7.0 – 8.9 |
| Medium | 8 | 4.0 – 6.9 |
| Low | 3 | 0.1 – 3.9 |

**Risk bands:**

| Band | Score Range |
|------|-------------|
| Critical | R ≥ 75 |
| High | 50 ≤ R < 75 |
| Medium | 25 ≤ R < 50 |
| Low | R < 25 |

Weights are configurable via `scoring/weights.json` for organisation-specific risk tolerance.

---

## Getting Started

### Option A — Direct browser (recommended, no install)

```bash
git clone https://github.com/youness-lahdiri01/Android-Attack-Surface-Mapper.git
cd Android-Attack-Surface-Mapper
# Open index.html in Chrome ≥ 90 or Firefox ≥ 88
open index.html   # macOS
xdg-open index.html  # Linux
```

### Option B — Local development server

```bash
npm install
npm start
# Open http://localhost:3000
```

Requires **Node.js ≥ 16**.

### Option C — AI-assisted remediation (Layer 4)

1. Obtain an [Anthropic API key](https://console.anthropic.com/)
2. Add it to `config.js`:

```js
// config.js
const CONFIG = {
  ANTHROPIC_API_KEY: "sk-ant-...",
  MODEL: "claude-sonnet-4-20250514"
};
```

If no key is set, Layer 4 is gracefully disabled — Layers 1–3 remain fully functional.

---

## Usage

1. **Upload** — drag and drop an APK file onto the interface, or select it via the file picker. You can also paste a raw `AndroidManifest.xml` directly.
2. **Review components** — the manifest panel shows package metadata, SDK versions, security flag badges, and a full enumeration of exported components.
3. **Check the risk score** — the score gauge shows the computed risk score and severity breakdown (Critical / High / Medium / Low counts).
4. **Explore findings** — each detected issue is listed as a severity-badged card with a description and remediation hint.
5. **Inspect the attack graph** — the interactive D3.js graph renders:
   - **Blue nodes** — Activities
   - **Purple nodes** — Services
   - **Amber nodes** — Broadcast Receivers
   - **Red nodes** — Content Providers
   - **Solid red edges** — exported components without permission guard (direct attack surface)
   - **Dashed blue edges** — intent-filter linkages (implicit reachability)
   - Node size is proportional to the number of associated findings.
6. **Get AI fixes** *(Layer 4)* — click **Ask AI** on any finding card for a context-aware explanation, ready-to-paste XML patch, alternative permission-based fix, and effort estimate.
7. **Export** — download the full report as PDF or plain text.

> **Important:** AI-generated guidance is indicative and must be validated by a qualified security professional before deployment.

---

## AI-Assisted Remediation (Layer 4)

When **Ask AI** is triggered, only the following structured metadata is transmitted to the Anthropic Claude API — **no APK binary, no manifest content, no user-identifiable data**:

```json
{
  "component": "DoTransfer",
  "misconfiguration": "EXPORTED_ACTIVITY_NO_PERMISSION",
  "package": "com.android.insecurebankv2",
  "targetSdkVersion": 22
}
```

The assistant returns:
- A natural-language explanation of the vulnerability and its exploitation scenario
- A ready-to-paste XML manifest patch
- An alternative permission-based remediation (where applicable)
- An effort estimate (Low / Medium / High)
- Suggested follow-up questions

The model endpoint (`claude-sonnet-4-20250514`) is configurable in `config.js` to allow substitution with alternative providers.

---

## Benchmark Results

Evaluated on a controlled set of 10 APK samples (5 misconfigured, 5 clean). Ground-truth labels established by human expert review.

| Metric | Android Attack Surface Mapper | Expert Review |
|--------|-------------------------------|---------------|
| Precision | **1.000** | 1.000 |
| Recall | **0.900** | 1.000 |
| F1-Score | **0.947** | 1.000 |
| Avg. analysis time | **< 2 s** | ~15 min |

**Confusion matrix** (per-sample, binary: misconfigured / clean): TP = 5, FP = 0, FN = 1, TN = 5.

The single false negative corresponds to **Urdu Fake App**, whose `exported` attribute was set programmatically at runtime rather than declared statically in the manifest — a fundamental limitation of static analysis.

**Reproduce the benchmark:**

```bash
node benchmark/run_benchmark.js
# Expected: Precision: 1.000 | Recall: 0.900 | F1: 0.947
```

> These results are preliminary and computed on a small controlled dataset. They should not be generalised without evaluation on larger, more diverse corpora (e.g. AndroZoo, Drebin).

SHA-256 checksums for all samples are in `CHECKSUMS.md`. The malware sample (Urdu Fake App) is not redistributed — retrieve it independently from [AndroZoo](https://androzoo.uni.lu/) using the hash in `CHECKSUMS.md`.

---

## Testing

```bash
npm install
npm test
# Expected: 20 passing
```

Unit tests cover each of the 10 detection rules with both a misconfigured (positive) and a correctly configured (negative) manifest example. Located in `test/rules.test.js`.

---

## Limitations

1. **Small benchmark** — 10 samples are insufficient for statistically robust conclusions; extended evaluation on AndroZoo and Drebin is planned.
2. **Static analysis only** — runtime misconfigurations (e.g. `setExported(true)`, dynamic permission grants) are not detectable.
3. **Manifest scope only** — native code (`.so`) and bytecode-level patterns (e.g. hardcoded secrets in Smali/DEX) are out of scope.
4. **External LLM dependency** — Layer 4 depends on external API availability and incurs costs that vary by provider.
5. **No post-patch verification** — the tool does not re-analyse the manifest after AI-suggested fixes are applied.
6. **AXML scope** — encrypted or obfuscated manifests (from certain packers) are out of scope for v2.0.0.

---

## Roadmap

- [ ] Extended evaluation on AndroZoo and Drebin datasets
- [ ] Bytecode-level analysis of DEX files
- [ ] Android App Bundle (AAB) format support
- [ ] Dynamic analysis integration via ADB hooking
- [ ] REST API mode for CI/CD pipeline integration
- [ ] GitHub Actions / GitLab CI plugin
- [ ] Per-rule false positive suppression via custom permission evaluation

---

## Contributing

Contributions are welcome. To add a new detection rule:

1. Create a plain JavaScript object conforming to the interface defined in `src/rules/rule_schema.js`.
2. Drop it into `src/rules/`.
3. Add corresponding positive and negative test cases in `test/rules.test.js` (2 per rule).
4. Run `npm test` to verify all tests pass.

No modifications to core parsing, visualization, or scoring layers are required.

---

## Citation

If you use this tool in academic work, please cite:

```bibtex
@software{lahdiri2025androidasm,
  author    = {Lahdiri, Youness and Kabbaj, Amine},
  title     = {Android Attack Surface Mapper v2.0.0},
  year      = {2025},
  publisher = {Zenodo},
  doi       = {10.5281/zenodo.20090644},
  url       = {https://github.com/youness-lahdiri01/Android-Attack-Surface-Mapper}
}
```

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

*Support: aminekabbaj144@gmail.com*
