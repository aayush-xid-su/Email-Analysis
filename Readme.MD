# MailRecon

<p align="center">
  <img src="./public/mail.png" width="160" alt="MailRecon">
</p>

<h3 align="center">Email Threat Intelligence & SOC Analysis Platform</h3>

<p align="center">
  AI-powered email forensics platform for analyzing EML files, investigating phishing campaigns, extracting IOCs, validating SPF/DKIM/DMARC records, and generating security reports.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/React-19-blue" />
  <img src="https://img.shields.io/badge/TypeScript-Latest-blue" />
  <img src="https://img.shields.io/badge/Node.js-Backend-green" />
  <img src="https://img.shields.io/badge/Google-Gemini-orange" />
  <img src="https://img.shields.io/badge/License-MIT-success" />
</p>

---

## 📖 Overview

MailRecon is a modern Email Threat Intelligence & Forensics platform designed for SOC analysts, cybersecurity researchers, incident responders, and security teams.

The platform enables users to upload `.eml` files, inspect email headers, validate SPF/DKIM/DMARC records, extract Indicators of Compromise (IOCs), investigate phishing attempts, and generate AI-powered threat intelligence reports using Google Gemini.

---

## 🚀 Key Features

### 📧 Deep MIME Parser & Header Alignments
- Reconstructs complete SMTP transmission paths and email relay chains.
- Performs in-depth MIME structure analysis for multipart messages and attachments.
- Validates core email authentication mechanisms:
  - SPF Verification
  - DKIM Signature Validation
  - DMARC Policy Enforcement
- Detects spoofing attempts, authentication failures, and header inconsistencies.

### 🧠 Security Context Triage (AI-Powered)
- Powered by **Google Gemini** using the modern **@google/genai** SDK.
- Performs contextual analysis of email content beyond traditional signature-based detection.
- Identifies:
  - Spear-phishing tactics
  - Business Email Compromise (BEC) indicators
  - Social engineering patterns
  - Brand impersonation attempts
  - Suspicious domain behaviors
- Generates analyst-friendly investigation summaries and containment recommendations.

### 🔍 Decoupled IOC Extraction & Registry
- Automatically extracts and catalogs Indicators of Compromise (IOCs).
- Supports detection and indexing of:
  - Malicious URLs
  - Suspicious IP Addresses
  - Rogue Domains
  - SHA-256 Hashes
  - MD5 Hashes
  - Email Addresses
- Centralized **IOC Explorer** enables rapid threat hunting and correlation.

### 🔐 Zero-Trust Live Gmail Connection Hub
- Secure Gmail integration through authenticated OAuth workflows.
- Directly retrieves incoming messages for analysis without storing user credentials.
- Security-first architecture:
  - No client-side credential persistence
  - No password collection
  - Token-based authorization
  - Principle of least privilege access
- Supports real-time email inspection and monitoring workflows.

### ⚡ Threat Intelligence & Forensics
- Correlates extracted artifacts with threat intelligence context.
- Provides risk-based threat scoring and prioritization.
- Generates detailed forensic investigation reports.
- Accelerates incident response and phishing triage operations.

### 🛡 Enterprise Security Architecture
- Server-side AI processing ensures API key protection.
- Secure email content handling and sanitization.
- Designed around Zero-Trust security principles.
- Supports SOC, Threat Hunting, DFIR, and Security Operations workflows.


## 🏗 Architecture

```text
┌────────────────────┐
│    Email Input     │
│ (.eml / Gmail API) │
└─────────┬──────────┘
          │
          ▼
┌────────────────────┐
│   Email Parser     │
└─────────┬──────────┘
          │
          ▼
┌────────────────────┐
│ Header Analysis    │
└─────────┬──────────┘
          │
          ▼
┌────────────────────┐
│ SPF / DKIM / DMARC │
└─────────┬──────────┘
          │
          ▼
┌────────────────────┐
│ IOC Extraction     │
└─────────┬──────────┘
          │
          ▼
┌────────────────────┐
│ Gemini AI Engine   │
└─────────┬──────────┘
          │
          ▼
┌────────────────────┐
│ Threat Intelligence│
└─────────┬──────────┘
          │
          ▼
┌────────────────────┐
│ Investigation Report│
└────────────────────┘
```


---

## 🚀 Installation

### Clone Repository

```bash
git clone https://github.com/order-by-ayush/Email-Analysis.git

cd Email-Analysis
```

### Install Dependencies

```bash
npm install
```

### Configure Environment Variables

Create a `.env` file in the project root:

```env
GEMINI_API_KEY=your_google_gemini_api_key
```

## Run Development Server

```bash
npm run dev
```

Application will be available at:

```text
http://localhost:3000
```

---

## 📨 How to Implement Live Gmail Integration

MailRecon allows you to link your active Google Workspace or personal inbox securely using two direct connection channels. Since all simulators have been deactivated, connecting a live inbox will render real, direct mailbox traffic.

### Options A: Google Developer API Playground (Recommended for quick testing)

This is the fastest, zero-setup method to query your live inbox without provisioning a Google Cloud Project or managing Client certificates.

1.  Go to the **[Google OAuth 2.0 Playground](https://developers.google.com/oauthplayground/)**.
2.  In the panel on the left (Step 1: Select & authorize APIs):
    *   Scroll down to find and expand **Gmail API v1**.
    *   Check the scope: `https://www.googleapis.com/auth/gmail.readonly`.
3.  Click the blue **Authorize APIs** button. You will be redirected to the official Google Account Selector interface. Select the Google account you wish to audit.
4.  Once returned to the Playground (Step 2: Exchange authorization code for tokens):
    *   Click the blue **Exchange authorization code for tokens** button.
5.  Under the resulting "Step 2" or "Step 3" values, locate the text area containing the **Access Token** field (it starts with `ya29....`).
6.  Copy that token string.
7.  Return to **MailRecon**, switch your connection tab to **Playground Token Helper**, enter your Gmail address and paste the Access Token, then click **Authenticate Live Bearer Token**.

Your application will immediately initialize a real-time HTTPS pipeline to fetch up to 10 incoming mail headers.

---

### Option B: Configure Live OAuth Client ID (For permanent deployment)

If you have a Google Cloud Platform console account and wish to authorize standard, multi-user sign-ins:

1.  Open the **[Google Cloud Console](https://console.cloud.google.com/)** and select/create a project.
2.  Navigate to **APIs & Services** > **Library**, search for "Gmail API", and click **Enable**.
3.  Go to **APIs & Services** > **OAuth Consent Screen**:
    *   Set the User Type (typically *External* for standalone audits).
    *   Add yours or other tester emails as Authorized Testers.
    *   Add the `gmail.readonly` scope (`https://www.googleapis.com/auth/gmail.readonly`).
4.  Navigate to **APIs & Services** > **Credentials**:
    *   Click **+ Create Credentials** and select **OAuth Client ID**.
    *   Pick **Web Application** as the application type.
    *   Under **Authorized JavaScript origins**, add your development or production URL (e.g. `https://ais-dev-aarpsn7ybhrdlinn2pygfe-598395949023.asia-southeast1.run.app`).
5.  Copy the generated **Client ID** (it ends in `.apps.googleusercontent.com`).
6.  In **MailRecon**, keep the tab on **Google OAuth Login**, paste your Client ID, and click **Sign in with Google**.
7.  Select your credentials through Google's pop-up and grant the read-only Gmail access prompt.



## 📈 Workflow

```text
Email Upload
      │
      ▼
Header Parsing
      │
      ▼
SPF / DKIM / DMARC Analysis
      │
      ▼
IOC Extraction
      │
      ▼
AI Threat Investigation
      │
      ▼
Threat Scoring
      │
      ▼
Investigation Report
```

---

## 📋 Core Modules

| Module | Description |
|----------|-------------|
| DashboardView | Security Operations dashboard |
| AnalyzeWorkspace | Email analysis workspace |
| GmailHub | Gmail integration and monitoring |
| IocExplorer | IOC investigation interface |
| ThreatMeter | Threat scoring visualization |
| MailRelayFlow | SMTP relay chain analysis |
| ReportView | Detailed forensic reports |
| SettingsView | Application configuration |

---


## 🤝 Contributing

Contributions are welcome.

1. Fork the repository
2. Create a feature branch

```bash
git checkout -b feature/new-feature
```

3. Commit changes

```bash
git commit -m "Add new feature"
```

4. Push branch

```bash
git push origin feature/new-feature
```

5. Open a Pull Request

---

## 📜 License

This project is licensed under the MIT License.

---

## 👨‍💻 Author

**Ayush Das**

GitHub: https://github.com/aayush-xid-su

---

## ⚠ Disclaimer

This project is intended for defensive security, email forensics, incident response, research, and educational purposes only.

Users are responsible for complying with all applicable laws, regulations, and organizational security policies.

---

<p align="center">
  Made with ❤️ for Cybersecurity Professionals
</p>
