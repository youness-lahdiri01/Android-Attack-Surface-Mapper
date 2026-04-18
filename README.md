# Android Attack Surface Mapper

## Overview

Android Attack Surface Mapper is a security analysis tool designed to audit Android applications by analyzing APK files or AndroidManifest.xml directly in the browser.

The tool performs a fully local analysis without requiring any API keys or external services, ensuring that no data leaves the user's machine.

## Features

- Upload and analyze APK files
- Automatic extraction of AndroidManifest.xml
- Static security analysis
- Detection of multiple vulnerability categories
- Risk score calculation (0–100)
- Attack surface visualization (graph)
- Detailed security report generation

## Installation

Clone the repository:

git clone https://github.com/youness-lahdiri01/Android-Attack-Surface-Mapper.git

Navigate to the project directory:

cd Android-Attack-Surface-Mapper

Install dependencies:

npm install

Start the server:

npm start

## Usage

Open a browser and go to:

http://localhost:3000

Upload an APK file using drag and drop. The tool will automatically extract the manifest, analyze components, detect vulnerabilities, and display the results including risk score, findings, and attack graph.

## Detected Vulnerabilities

- Debuggable enabled
- Exported components without permission
- Exposed ContentProvider
- allowBackup enabled
- Cleartext traffic enabled
- Unverified deep links
- Dangerous permissions
- Implicit component export

## Risk Score

- 0–29: Low risk
- 30–69: Medium risk
- 70–100: High risk

## Project Structure

```
android-attack-surface-mapper/
│
├── public/                # Frontend logic (runs in browser)
│   ├── axml.js            # Binary Android XML decoder
│   ├── apk.js             # APK loader and extractor
│   ├── parser.js          # Manifest parser
│   ├── findings.js        # Security checks engine
│   ├── graph.js           # Attack graph generator
│   └── app.js             # Main application controller
│
├── server/                # Backend (static server)
│   └── index.js           # Express server
│
├── package.json           # Project dependencies and scripts
```

## Security

The tool operates entirely locally. No data is transmitted to external servers and no API keys are required.
## Example and Screenshots

The following example demonstrates how the tool analyzes an APK and presents the results.

### Step 1: Upload APK

The user uploads an APK file using the drag-and-drop interface.

### Step 2: Analysis Results

After processing, the tool extracts the AndroidManifest.xml and displays key information including components and permissions.

<img width="1307" height="886" alt="Screenshot 2026-04-18 205736" src="https://github.com/user-attachments/assets/63a73317-5b41-4f6c-93d3-61cec9d41332" />

### Step 3: Detected Vulnerabilities

The tool identifies security issues such as exported components, insecure configurations, and dangerous permissions.

<img width="1356" height="871" alt="Screenshot 2026-04-18 205750" src="https://github.com/user-attachments/assets/dc17641e-74ce-415a-863d-ed4f1a7fb675" />

### Step 4: Attack Surface Graph

A visual representation of the attack surface is generated, showing exposed components and their relationships.

<img width="1158" height="439" alt="Screenshot 2026-04-18 205652" src="https://github.com/user-attachments/assets/706a6a75-21f0-40c9-954a-d62e5c958311" />

### Step 5: Security Report

A complete report is generated including the risk score and remediation recommendations.

<img width="1307" height="886" alt="Screenshot 2026-04-18 205736" src="https://github.com/user-attachments/assets/ef3d808d-7a00-43fa-a1ad-bd2d6c673a3a" />


## Future Improvements

- Support for AAB files
- Dynamic analysis capabilities
- CI/CD integration
- Advanced detection techniques
- 

## Author

Youness Lahdiri
Amine KABBAJ
