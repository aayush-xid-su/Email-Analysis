/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useRef } from "react";
import { 
  Upload, 
  Terminal, 
  FileCode, 
  ChevronRight, 
  Play, 
  HelpCircle, 
  CheckCircle,
  FileText,
  AlertCircle
} from "lucide-react";

interface AnalyzeWorkspaceProps {
  onAnalyzeUploaded: (fileName: string, content: string) => Promise<any>;
  onAnalyzePasted: (subject: string, content: string) => Promise<any>;
}

export default function AnalyzeWorkspace({ 
  onAnalyzeUploaded, 
  onAnalyzePasted 
}: AnalyzeWorkspaceProps) {
  const [activeTab, setActiveTab] = useState<"upload" | "paste">("upload");
  const [dragActive, setDragActive] = useState(false);
  const [pastedSubject, setPastedSubject] = useState("");
  const [pastedContent, setPastedContent] = useState("");
  const [loading, setLoading] = useState(false);
  const [loadingStep, setLoadingStep] = useState("");
  const [errorMessage, setErrorMessage] = useState("");

  const fileInputRef = useRef<HTMLInputElement>(null);

  // SMTP Tactical Sample seeds for instant clicking trials
  const SAMPLE_EML_PHISHING = `Received: from mail-issuer.secured-banking-alert.com ([198.51.100.22])
by mx.google.com with ESMTPS id o10si228392plh.122
for <victim@corporation.internal>; Mon, 01 Mar 2026 14:24:10 GMT
Received-SPF: fail (google.com: domain of support@banking-alert.com does not designate 198.51.100.22 as permitted sender)
DKIM-Signature: v=1; a=rsa-sha256; c=simple/simple; d=secured-banking-alert.com;
From: "National Bank Security Security Service" <support@banking-alert.com>
To: <target.analyst@corporation.internal>
Subject: Security Alert: Your online banking access is temporarily suspended - Action required
Date: Mon, 01 Mar 2026 14:15:22 -0600
Reply-To: <claims-service-dept@g-mail-support.net>
Return-Path: <bounce-daemon@secured-banking-alert.com>
Message-ID: <881273921.abc883011a@banking-alert.com>

Dear Credit Customer,

We detected anomalous transactions and credential changes on your active checking accounts.
To secure your assets, you must click our direct database sync authentication link immediately:
http://secured-banking-alert.com/confirm-auth/login.php

Failure to verify within 12 banking hours results in asset hold freezing.

Sincerely,
National Trust Audit Committee.`;

  const SAMPLE_EML_TROJAN = `Received: from relay-internal.invoice-gateway.net ([192.0.2.14])
by gatekeeper.enterprise.net with SMTP id t892011a-mfa
for <accounting@corporation.internal>; Thu, 05 Mar 2026 09:12:05 GMT
Received-SPF: pass (relay-internal.invoice-gateway.net aligned)
DKIM-Signature: v=1; a=rsa-sha256; d=invoice-gateway.net; s=selector12;
From: "Invoicing & Financial Receivables" <accounts-payable@invoice-gateway.net>
To: <accounting@corporation.internal>
Subject: Invoice GP-901-2026 for urgent settlement payment
Date: Thu, 05 Mar 2026 09:10:00 GMT
Message-ID: <918231920-inv@invoice-gateway.net>
Content-Type: multipart/mixed; boundary="BOUNDARY-NEXT-MIME-88392"

--BOUNDARY-NEXT-MIME-88392
Content-Type: text/plain; charset="utf-8"

Accounting Team,

Please resolve our Q1 billing invoice #GP-901-2026 attached below.
Let us know when payment draft is completed.

--BOUNDARY-NEXT-MIME-88392
Content-Type: application/vnd.ms-excel.sheet.macroEnabled.12; name="Invoice-Receipt_8832.xlsm"
Content-Disposition: attachment; filename="Invoice-Receipt_8832.xlsm"
Content-Transfer-Encoding: base64

Active script payload simulation bytes.

--BOUNDARY-NEXT-MIME-88392--`;

  const SAMPLE_EML_CLEAN = `Received: from out-15.smtp.github.com ([140.82.115.15])
by mx.google.com with ESMTPS id gh-228392plha
for <developer@corporation.internal>; Sun, 10 May 2026 21:05:12 GMT
Received-SPF: pass (google.com: domain of noreply@github.com designates 140.82.115.15 as permitted sender)
DKIM-Signature: v=1; a=rsa-sha256; d=github.com; s=enterprise-key;
From: "GitHub Security Alert" <noreply@github.com>
To: <developer@corporation.internal>
Subject: [GitHub] Alert: New deployment key registered successfully
Date: Sun, 10 May 2026 21:04:15 GMT
Message-ID: <deploy-alert-12839211@github.com>

Hi Dev,

A new deploy key has been registered on your account settings.
Review key configurations on our safe portal page:
https://github.com/settings/keys

Thanks,
GitHub security department.`;

  // Simulate scanning phases with user progress
  const runForensicScannerSimulation = async (callback: () => Promise<any>) => {
    setLoading(true);
    setErrorMessage("");
    const steps = [
      "Extracting MIME content and raw header vectors...",
      "Analyzing SMTP relay chain and parsing Received: hops...",
      "Cross-referencing domain age and registrar reputations...",
      "Filtering active embedded URLs and macro-checking Excel sheets...",
      "Synthesizing forensic security report with server-side AI..."
    ];

    try {
      for (let i = 0; i < steps.length; i++) {
        setLoadingStep(steps[i]);
        await new Promise((resolve) => setTimeout(resolve, i === 4 ? 1200 : 450));
      }
      await callback();
    } catch (err: any) {
      setErrorMessage(err.message || "Threat analyzer aborted: Failed compiling email diagnostics.");
      setLoading(false);
    }
  };

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true);
    } else if (e.type === "dragleave") {
      setDragActive(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);

    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      processSelectedFile(e.dataTransfer.files[0]);
    }
  };

  const handleFileInput = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      processSelectedFile(e.target.files[0]);
    }
  };

  const processSelectedFile = (file: File) => {
    const isEml = file.name.endsWith(".eml") || file.name.endsWith(".txt") || file.type.includes("message/rfc822");
    if (!isEml) {
      setErrorMessage("File format warning: Platform prefers RFC822 EML files or plain text headers.");
      return;
    }

    const reader = new FileReader();
    reader.onload = async (event) => {
      const text = event.target?.result as string;
      await runForensicScannerSimulation(async () => {
        await onAnalyzeUploaded(file.name, text);
      });
    };
    reader.readAsText(file);
  };

  const submitPastedText = async () => {
    if (!pastedContent.trim()) {
      setErrorMessage("Forensics queue error: Pasted headers area cannot be left empty.");
      return;
    }

    await runForensicScannerSimulation(async () => {
      await onAnalyzePasted(pastedSubject, pastedContent);
    });
  };

  const triggerSampleLoad = async (sampleType: "phishing" | "trojan" | "clean") => {
    let content = "";
    let name = "";
    let subject = "";

    switch (sampleType) {
      case "phishing":
        content = SAMPLE_EML_PHISHING;
        name = "suspicious_banking_credentials.eml";
        subject = "Urgent Bank account locked";
        break;
      case "trojan":
        content = SAMPLE_EML_TROJAN;
        name = "invoice_receiving_active_macros.eml";
        subject = "Settlement Outstanding Invoice GP-901";
        break;
      case "clean":
        content = SAMPLE_EML_CLEAN;
        name = "github_ssh_key_alignment.eml";
        subject = "[GitHub] SSH Register Confirmation";
        break;
    }

    setActiveTab("paste");
    setPastedSubject(subject);
    setPastedContent(content);

    // Dynamic scanner direct trigger
    await runForensicScannerSimulation(async () => {
      await onAnalyzeUploaded(name, content);
    });
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
      {/* Workspace Controls */}
      <div className="lg:col-span-2 bg-slate-900/40 border border-slate-800 rounded-xl overflow-hidden flex flex-col justify-between">
        
        {/* Workspace navigation headers */}
        <div className="border-b border-slate-800 bg-slate-900/60 p-1 flex">
          <button
            onClick={() => { setActiveTab("upload"); setErrorMessage(""); }}
            className={`flex-1 py-3 text-xs font-mono font-medium flex items-center justify-center gap-2 border-b-2 transition-all cursor-pointer ${
              activeTab === "upload" 
                ? "border-cyan-500 text-white bg-slate-800/20" 
                : "border-transparent text-slate-400 hover:text-slate-300 hover:bg-slate-800/10"
            }`}
          >
            <Upload className="w-4 h-4 text-cyan-500" />
            DRAG & DROP EML FILES
          </button>
          <button
            onClick={() => { setActiveTab("paste"); setErrorMessage(""); }}
            className={`flex-1 py-3 text-xs font-mono font-medium flex items-center justify-center gap-2 border-b-2 transition-all cursor-pointer ${
              activeTab === "paste" 
                ? "border-cyan-500 text-white bg-slate-800/20" 
                : "border-transparent text-slate-400 hover:text-slate-300 hover:bg-slate-800/10"
            }`}
          >
            <Terminal className="w-4 h-4 text-cyan-400" />
            PASTE RAW SMTP HEADERS
          </button>
        </div>

        {/* Workspace body panels */}
        <div className="p-6 flex-1 flex flex-col justify-center">
          
          {loading ? (
            /* Analysis Progress indicator panel */
            <div className="py-12 flex flex-col items-center justify-center text-center select-none">
              <div className="relative w-16 h-16 mb-6">
                <div className="absolute inset-0 rounded-full border-4 border-cyan-500/10 border-t-cyan-400 animate-spin" />
                <div className="absolute inset-0 rounded-full border-4 border-slate-800 scale-90" />
                <div className="absolute inset-0 flex items-center justify-center">
                  <FileCode className="w-5 h-5 text-cyan-500 animate-bounce" />
                </div>
              </div>

              <h3 className="font-sans font-bold text-sm text-white">MailRecon Engine Active</h3>
              <p className="font-mono text-[10px] text-cyan-400 max-w-sm mt-1.5 min-h-[20px]">
                {loadingStep}
              </p>

              <div className="w-64 h-1 bg-slate-950 rounded-full mt-6 overflow-hidden">
                <div className="h-full bg-cyan-500 rounded-full animate-pulse w-3/4" />
              </div>
            </div>
          ) : activeTab === "upload" ? (
            /* File Upload Module */
            <div 
              onDragEnter={handleDrag}
              onDragOver={handleDrag}
              onDragLeave={handleDrag}
              onDrop={handleDrop}
              onClick={() => fileInputRef.current?.click()}
              className={`border-2 border-dashed rounded-xl p-12 text-center flex flex-col items-center justify-center transition-all cursor-pointer select-none group ${
                dragActive 
                  ? "border-cyan-500 bg-cyan-950/15" 
                  : "border-slate-800 bg-slate-950/20 hover:border-slate-700 hover:bg-slate-950/35"
              }`}
            >
              <input 
                type="file" 
                ref={fileInputRef}
                onChange={handleFileInput}
                accept=".eml,.txt,message/rfc822"
                className="hidden" 
              />
              <div className="p-4 rounded-full bg-slate-900 border border-slate-800 group-hover:border-slate-700 transition-colors mb-4 text-cyan-400 group-hover:scale-105 transform duration-300">
                <Upload className="w-6 h-6" />
              </div>
              <h3 className="font-sans font-semibold text-xs text-white">
                Drag and drop SMTP EML file here
              </h3>
              <p className="text-[10px] text-slate-500 mt-1 max-w-xs">
                Supports RFC822 email format exports (.eml) or raw forensic header text dumps. Max size 15MB.
              </p>
              <span className="mt-4 px-3 py-1 bg-slate-900 border border-slate-800 rounded group-hover:text-white group-hover:bg-slate-800 text-[10px] text-slate-400 font-mono transition-colors">
                Browse Files
              </span>
            </div>
          ) : (
            /* Paste Raw Content tab */
            <div className="space-y-4">
              <div>
                <label className="block text-[10px] font-mono text-slate-400 uppercase tracking-wider mb-1.5">
                  Optional Custom Subject Case
                </label>
                <input
                  type="text"
                  placeholder="e.g., Security incident tracking: credential audit inquiry"
                  value={pastedSubject}
                  onChange={(e) => setPastedSubject(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg border border-slate-800 bg-slate-950/80 font-sans text-xs text-white placeholder-slate-600 outline-none focus:border-cyan-500/40 transition-colors"
                />
              </div>

              <div>
                <label className="block text-[10px] font-mono text-slate-400 uppercase tracking-wider mb-1.5">
                  Paste Raw RFC822 Headers & Message Content
                </label>
                <textarea
                  placeholder="Paste complete SMTP headers list here (including Date, From, Received headers, etc.) next to original email text body..."
                  rows={9}
                  value={pastedContent}
                  onChange={(e) => setPastedContent(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg border border-slate-800 bg-slate-950/80 font-mono text-xs text-slate-300 placeholder-slate-600 outline-none focus:border-cyan-500/40 focus:bg-slate-950 transition-colors"
                />
              </div>

              {errorMessage && (
                <div className="p-3 bg-rose-500/10 border border-rose-500/20 rounded-lg flex items-start gap-2 text-rose-400 text-xs">
                  <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
                  <span>{errorMessage}</span>
                </div>
              )}

              <button
                onClick={submitPastedText}
                className="w-full py-2.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-sans font-bold text-xs flex items-center justify-center gap-1.5 transition-colors cursor-pointer active:scale-95 duration-200 shadow-md shadow-cyan-950/10"
              >
                <Play className="w-4 h-4" />
                Initiate Forensic Sequence
              </button>
            </div>
          )}

          {errorMessage && activeTab === "upload" && (
            <div className="mt-4 p-3 bg-rose-500/10 border border-rose-500/20 rounded-lg flex items-start gap-2 text-rose-400 text-xs">
              <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
              <span>{errorMessage}</span>
            </div>
          )}
        </div>
      </div>

      {/* Cyber Intelligence Presets Sidebar */}
      <div className="space-y-4">
        <div className="bg-slate-900/40 border border-slate-800 p-5 rounded-xl">
          <h3 className="font-sans font-medium text-xs tracking-wider text-slate-400 uppercase mb-3 flex items-center gap-1.5">
            <HelpCircle className="w-4 h-4 text-cyan-400" />
            Tactical Analysis Seeding
          </h3>
          <p className="text-[10px] text-slate-400 leading-relaxed mb-4">
            No incident dumps handy? Click any pre-configured attack vector payload to seed a live forensic inspection instantly:
          </p>

          <div className="space-y-3">
            {/* Phishing Preset */}
            <button
              onClick={() => triggerSampleLoad("phishing")}
              disabled={loading}
              className="w-full p-3 rounded-lg border border-rose-500/10 bg-rose-950/5 hover:bg-rose-950/15 text-left border hover:border-rose-500/30 transition-all cursor-pointer flex items-center justify-between group"
            >
              <div className="min-w-0 pr-2">
                <div className="text-[10px] font-mono text-rose-400 font-semibold uppercase tracking-wider">A: Phishing Scam</div>
                <div className="text-xs font-bold text-white truncate mt-0.5">National Bank suspension portal Alert</div>
                <div className="text-[9px] text-slate-500 mt-1 truncate">SPF verification failures • Spoofed Reply path</div>
              </div>
              <ChevronRight className="w-4 h-4 text-rose-500 group-hover:translate-x-1 transition-transform shrink-0" />
            </button>

            {/* Trojan Presets */}
            <button
              onClick={() => triggerSampleLoad("trojan")}
              disabled={loading}
              className="w-full p-3 rounded-lg border border-purple-500/10 bg-purple-950/5 hover:bg-purple-950/15 text-left border hover:border-purple-500/30 transition-all cursor-pointer flex items-center justify-between group"
            >
              <div className="min-w-0 pr-2">
                <div className="text-[10px] font-mono text-purple-400 font-semibold uppercase tracking-wider">B: Trojan Payload Delivery</div>
                <div className="text-xs font-bold text-white truncate mt-0.5">Settlement Invoice Receipt (.xlsm)</div>
                <div className="text-[9px] text-slate-500 mt-1 truncate">VBA active macro scripts • Double relays</div>
              </div>
              <ChevronRight className="w-4 h-4 text-purple-500 group-hover:translate-x-1 transition-transform shrink-0" />
            </button>

            {/* Clean SSH Keys Preset */}
            <button
              onClick={() => triggerSampleLoad("clean")}
              disabled={loading}
              className="w-full p-3 rounded-lg border border-cyan-500/10 bg-cyan-950/5 hover:bg-cyan-950/15 text-left border hover:border-cyan-500/30 transition-all cursor-pointer flex items-center justify-between group"
            >
              <div className="min-w-0 pr-2">
                <div className="text-[10px] font-mono text-cyan-400 font-semibold uppercase tracking-wider">C: Cryptographically Aligned</div>
                <div className="text-xs font-bold text-white truncate mt-0.5">[GitHub] Deploy Key registration alert</div>
                <div className="text-[9px] text-slate-500 mt-1 truncate">SPF PASS • DKIM PASS • Verified registrant</div>
              </div>
              <ChevronRight className="w-4 h-4 text-cyan-500 group-hover:translate-x-1 transition-transform shrink-0" />
            </button>
          </div>
        </div>

        {/* Diagnostic checklist specs info card */}
        <div className="bg-slate-900/20 border border-slate-800 p-4 rounded-xl space-y-3">
          <h4 className="font-sans font-semibold text-xs text-white">Parser Structural Inspections</h4>
          <ul className="space-y-2 text-[10px] text-slate-400">
            <li className="flex items-start gap-1.5">
              <CheckCircle className="w-3.5 h-3.5 text-cyan-500 mt-0.5 shrink-0" />
              <span>Full compliance decoding of SPF, DKIM, DMARC validation markings.</span>
            </li>
            <li className="flex items-start gap-1.5">
              <CheckCircle className="w-3.5 h-3.5 text-cyan-500 mt-0.5 shrink-0" />
              <span>Chronological reconstruction of SMTP Received relay chains.</span>
            </li>
            <li className="flex items-start gap-1.5">
              <CheckCircle className="w-3.5 h-3.5 text-cyan-500 mt-0.5 shrink-0" />
              <span>Cryptographic hasher and extension macros evaluation of attached binaries.</span>
            </li>
            <li className="flex items-start gap-1.5">
              <CheckCircle className="w-3.5 h-3.5 text-cyan-500 mt-0.5 shrink-0" />
              <span>Deep intelligence explanations processed through Gemini AI 3.5.</span>
            </li>
          </ul>
        </div>
      </div>
    </div>
  );
}
