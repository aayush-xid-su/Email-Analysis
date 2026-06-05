/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from "react";
import { 
  ArrowLeft, 
  Printer, 
  Copy, 
  Check, 
  Download, 
  ShieldAlert, 
  ShieldCheck, 
  Globe, 
  Link2, 
  Paperclip,
  Activity,
  User,
  ExternalLink,
  ChevronDown,
  ChevronUp,
  FileText
} from "lucide-react";
import { EmailAnalysis } from "../types";
import ThreatMeter from "./ThreatMeter";
import MailRelayFlow from "./MailRelayFlow";
import IocExplorer from "./IocExplorer";

interface ReportViewProps {
  report: EmailAnalysis;
  onBack: () => void;
  onDeleteReport: (id: string) => void;
}

export default function ReportView({ report, onBack, onDeleteReport }: ReportViewProps) {
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [showRawHeaders, setShowRawHeaders] = useState(false);
  const [copiedRawHeaders, setCopiedRawHeaders] = useState(false);

  const handleCopyHash = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 1500);
  };

  const handleTriggerPrint = () => {
    window.print();
  };

  const handleCopyRawHeaders = () => {
    // Isolate headers section from raw input
    const endIdx = report.rawInput.indexOf("\n\n");
    const hText = endIdx !== -1 ? report.rawInput.substring(0, endIdx) : report.rawInput;
    navigator.clipboard.writeText(hText);
    setCopiedRawHeaders(true);
    setTimeout(() => setCopiedRawHeaders(false), 2000);
  };

  // Badge styles helper
  const getValidationBadge = (result: string) => {
    switch (result) {
      case "PASS":
        return "bg-emerald-500/10 text-emerald-400 border-emerald-500/30";
      case "FAIL":
        return "bg-rose-500/10 text-rose-400 border-rose-500/30";
      default:
        return "bg-slate-800 text-slate-400 border-slate-700/60";
    }
  };

  // Tab management for Forensic Stream
  const [activeForensicTab, setActiveForensicTab] = useState<"raw" | "headers" | "iocs">("raw");
  const [copiedForensic, setCopiedForensic] = useState(false);

  // Isolate headers section once
  const endHeadersIdx = report.rawInput.indexOf("\n\n");
  const rawHeadersText = endHeadersIdx !== -1 ? report.rawInput.substring(0, endHeadersIdx) : report.rawInput;

  // Format key indicators representation for JSON tab
  const iocManifestText = JSON.stringify({
    caseId: report.id,
    timestamp: report.timestamp,
    threatLevel: report.threatScore.level.toUpperCase(),
    threatScore: report.threatScore.score,
    indicatorsCount: report.iocs.length,
    indicators: report.iocs.map(ioc => ({
      type: ioc.type.toUpperCase(),
      value: ioc.value,
      severity: ioc.severity.toUpperCase(),
      description: ioc.description,
      source: ioc.source
    }))
  }, null, 2);

  const getForensicTabContent = () => {
    switch (activeForensicTab) {
      case "headers":
        return rawHeadersText;
      case "iocs":
        return iocManifestText;
      case "raw":
      default:
        return report.rawInput;
    }
  };

  const getForensicBtnLabel = () => {
    if (copiedForensic) return "Copied to Clipboard!";
    switch (activeForensicTab) {
      case "headers":
        return "Copy Headers";
      case "iocs":
        return "Copy IOC Manifest";
      case "raw":
      default:
        return "Copy SMTP Stream";
    }
  };

  const handleCopyForensicContent = () => {
    navigator.clipboard.writeText(getForensicTabContent());
    setCopiedForensic(true);
    setTimeout(() => setCopiedForensic(false), 2000);
  };

  return (
    <div className="space-y-6 printable-report">
      {/* Top action and back ribbon */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800 pb-5 select-none print:hidden">
        <button
          onClick={onBack}
          className="px-3.5 py-1.5 rounded-lg border border-slate-800 bg-slate-900/40 hover:bg-slate-800 text-slate-400 hover:text-white text-xs font-mono flex items-center gap-1.5 transition-colors cursor-pointer"
        >
          <ArrowLeft className="w-4 h-4" />
          Back to Ground Hub
        </button>

        <div className="flex items-center gap-2">
          <button
            onClick={handleCopyRawHeaders}
            className="px-3 py-1.5 bg-slate-800 text-xs text-slate-300 rounded hover:bg-slate-700 font-mono flex items-center gap-1.5 cursor-pointer"
          >
            {copiedRawHeaders ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copiedRawHeaders ? "Headers Copied" : "Copy Raw Headers"}</span>
          </button>
          
          <button
            onClick={handleTriggerPrint}
            className="px-3 py-1.5 bg-cyan-600 font-sans font-semibold text-xs text-white rounded hover:bg-cyan-500 flex items-center gap-1.5 cursor-pointer"
          >
            <Printer className="w-3.5 h-3.5" />
            <span>Print Report (PDF)</span>
          </button>

          <button
            onClick={() => onDeleteReport(report.id)}
            className="px-3 py-1.5 border border-rose-500/20 bg-rose-500/5 hover:bg-rose-500/20 text-xs text-rose-400 rounded cursor-pointer transition-colors"
          >
            Archive File
          </button>
        </div>
      </div>

      {/* Main Email Metadata Header */}
      <div className="p-6 bg-slate-900/40 border border-slate-800 rounded-xl relative overflow-hidden">
        <div className="absolute top-0 right-0 w-48 h-48 bg-cyan-500/5 blur-3xl pointer-events-none" />
        
        <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2 mb-2">
              <span className="px-2 py-0.5 rounded text-[10px] font-mono border border-slate-700 bg-slate-800 text-slate-400 font-bold select-none">
                REPORT CASE ID: {report.id}
              </span>
              <span className="text-[10px] text-slate-500 font-mono select-none">
                • Classifying incoming payload telemetry
              </span>
            </div>
            <h2 className="font-sans font-extrabold text-lg text-white truncate text-glow-cyan">
              {report.headers.subject || "No Subject header detected"}
            </h2>
            <div className="mt-3 flex flex-wrap gap-y-1.5 gap-x-5 text-xs text-slate-300">
              <span className="truncate">
                <span className="text-slate-500 font-mono select-none">From:</span>{" "}
                <strong className="text-white font-mono">{report.headers.from}</strong>
              </span>
              <span className="truncate">
                <span className="text-slate-500 font-mono select-none">To:</span>{" "}
                <span className="font-mono">{report.headers.to}</span>
              </span>
              <span className="shrink-0">
                <span className="text-slate-500 font-mono select-none">Date:</span>{" "}
                <span className="font-mono text-slate-400">{report.headers.date}</span>
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Grid: Left Column (Threat + AI) • Right Column (Header Badges & Details) */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Left 2 Columns: Scoring & AI explanations */}
        <div className="lg:col-span-2 space-y-6">
          
          {/* Threat Meter Circular Visual */}
          <ThreatMeter score={report.threatScore} />

          {/* AI Explanations Summary Card */}
          <div className="p-6 bg-slate-900/40 border border-slate-800 rounded-xl relative overflow-hidden">
            {/* Ambient accent banner */}
            <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-cyan-500 via-indigo-500 to-rose-500" />
            
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-4 select-none pb-3 border-b border-slate-800/60">
              <div className="flex items-center gap-2">
                <div className={`p-1 px-1.5 rounded font-mono text-[9px] font-bold border ${
                  report.aiExplanation.isFallback 
                    ? "bg-amber-500/10 text-amber-400 border-amber-500/20" 
                    : "bg-cyan-500/10 text-cyan-400 border-cyan-500/20"
                }`}>
                  {report.aiExplanation.isFallback ? "LOCAL RULES BACKUP" : "GEMINI AI COPILOT"}
                </div>
                <h3 className="font-sans font-bold text-xs tracking-wider text-slate-400 uppercase">
                  CYBER THREAT COGNITIVE REPORT
                </h3>
              </div>
              {report.aiExplanation.engineName && (
                <span className="text-[10px] text-slate-500 font-mono">
                  {report.aiExplanation.engineName}
                </span>
              )}
            </div>

            {report.aiExplanation.isFallback && (
              <div className="mb-4 p-3 bg-amber-500/5 border border-amber-500/10 rounded-lg text-xs text-amber-300 font-sans flex items-start gap-2.5">
                <ShieldAlert className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                <div className="space-y-0.5">
                  <div className="font-mono font-bold text-[9px] uppercase text-amber-400 tracking-wider">MIME Analyser Resilience Protocol</div>
                  <p className="text-slate-400 text-[11px] leading-relaxed">
                    Cloud API reported peak model demand or loading issues. Handed threat analysis over to MailRecon local rules engine seamlessly.
                  </p>
                </div>
              </div>
            )}

            <div className="space-y-4">
              {/* Verdict Indicator */}
              <div className="p-3 bg-slate-950/60 border border-slate-800 rounded-lg">
                <div className="text-[10px] font-mono uppercase tracking-wider text-slate-500">Cognitive Forensic Assessment Verdict</div>
                <div className="text-sm font-bold text-white mt-1 select-all">{report.aiExplanation.verdict}</div>
              </div>

              {/* Cognitive Summary */}
              <div>
                <h4 className="text-xs font-mono text-cyan-400 font-bold uppercase mb-1.5">Executive Incident Summary</h4>
                <p className="text-xs text-slate-300 leading-relaxed bg-slate-950/20 border border-slate-900 p-3.5 rounded-lg select-all">
                  {report.aiExplanation.summary}
                </p>
              </div>

              {/* Key Indicators of maliciousness */}
              <div>
                <h4 className="text-xs font-mono text-rose-400 font-bold uppercase mb-1.5">MIME Malicious Indicators Identified</h4>
                <ul className="space-y-2">
                  {report.aiExplanation.reasons.map((reason, idx) => (
                    <li key={idx} className="flex items-start gap-2 text-xs text-slate-300 leading-snug">
                      <span className="w-1.5 h-1.5 rounded-full bg-rose-500 mt-1.5 shrink-0" />
                      <span>{reason}</span>
                    </li>
                  ))}
                </ul>
              </div>

              {/* Action Recommendations for SOC */}
              <div className="border-t border-slate-800/80 pt-4">
                <h4 className="text-xs font-mono text-emerald-400 font-bold uppercase mb-1.5">SOC Immediate Mitigation Steps</h4>
                <ul className="space-y-2">
                  {report.aiExplanation.recommendations.map((rec, idx) => (
                    <li key={idx} className="flex items-start gap-2 text-xs text-slate-300 leading-snug">
                      <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 mt-1.5 shrink-0" />
                      <span>{rec}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          </div>
        </div>

        {/* Right Column: Key verification badges, Sender details, files sizes */}
        <div className="space-y-6">
          
          {/* Email Authentication Badges Overview */}
          <div className="p-5 bg-slate-900/40 border border-slate-800 rounded-xl space-y-4">
            <h3 className="font-sans font-medium text-xs tracking-wider text-slate-400 uppercase flex items-center gap-1.5">
              <ShieldCheck className="w-4 h-4 text-cyan-400" />
              SMTP CRYPTO COMPLIANCE
            </h3>

            {/* SPF Badge */}
            <div className={`p-3 rounded-lg border flex flex-col sm:flex-row sm:items-center justify-between gap-3 ${getValidationBadge(report.headers.spf.result)}`}>
              <div className="space-y-0.5">
                <div className="font-mono text-[10px] font-bold uppercase tracking-wider flex items-center flex-wrap gap-2">
                  <span>SPF Alignment Check</span>
                  {report.headers.spfAlignment && (
                    <span className={`text-[8px] px-1.5 py-0.5 rounded font-mono font-bold leading-none ${
                      report.headers.spfAlignment === 'PASS' 
                        ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/20' 
                        : report.headers.spfAlignment === 'FAIL' 
                        ? 'bg-red-500/15 text-red-400 border border-red-500/20'
                        : 'bg-slate-800 text-slate-500'
                    }`}>
                      ALIGNMENT: {report.headers.spfAlignment}
                    </span>
                  )}
                </div>
                <div className="text-[10px] text-slate-400 mt-0.5 leading-snug">{report.headers.spf.detail}</div>
              </div>
              <span className="font-mono text-xs font-extrabold px-2 py-0.5 rounded border bg-slate-950/60 shrink-0 self-end sm:self-auto">
                {report.headers.spf.result}
              </span>
            </div>

            {/* DKIM Badge */}
            <div className={`p-3 rounded-lg border flex flex-col sm:flex-row sm:items-center justify-between gap-3 ${getValidationBadge(report.headers.dkim.result)}`}>
              <div className="space-y-0.5">
                <div className="font-mono text-[10px] font-bold uppercase tracking-wider flex items-center flex-wrap gap-2">
                  <span>DKIM Signature Integrity Check</span>
                  {report.headers.dkimAlignment && (
                    <span className={`text-[8px] px-1.5 py-0.5 rounded font-mono font-bold leading-none ${
                      report.headers.dkimAlignment === 'PASS' 
                        ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/20' 
                        : report.headers.dkimAlignment === 'FAIL' 
                        ? 'bg-red-500/15 text-red-400 border border-red-500/20'
                        : 'bg-slate-800 text-slate-500'
                    }`}>
                      ALIGNMENT: {report.headers.dkimAlignment}
                    </span>
                  )}
                </div>
                <div className="text-[10px] text-slate-400 mt-0.5 leading-snug">{report.headers.dkim.detail}</div>
              </div>
              <span className="font-mono text-xs font-extrabold px-2 py-0.5 rounded border bg-slate-950/60 shrink-0 self-end sm:self-auto">
                {report.headers.dkim.result}
              </span>
            </div>

            {/* DMARC Badge */}
            <div className={`p-3 rounded-lg border flex flex-col sm:flex-row sm:items-center justify-between gap-3 ${getValidationBadge(report.headers.dmarc.result)}`}>
              <div className="space-y-0.5">
                <div className="font-mono text-[10px] font-bold uppercase tracking-wider flex items-center flex-wrap gap-2">
                  <span>DMARC Domain Alignment Check</span>
                  {report.headers.dmarcAlignment && (
                    <span className={`text-[8px] px-1.5 py-0.5 rounded font-mono font-bold leading-none ${
                      report.headers.dmarcAlignment === 'PASS' 
                        ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/20' 
                        : report.headers.dmarcAlignment === 'FAIL' 
                        ? 'bg-red-500/15 text-red-400 border border-red-500/20'
                        : 'bg-slate-800 text-slate-500'
                    }`}>
                      ALIGNMENT: {report.headers.dmarcAlignment}
                    </span>
                  )}
                </div>
                <div className="text-[10px] text-slate-400 mt-0.5 leading-snug">{report.headers.dmarc.detail}</div>
              </div>
              <span className="font-mono text-xs font-extrabold px-2 py-0.5 rounded border bg-slate-950/60 shrink-0 self-end sm:self-auto">
                {report.headers.dmarc.result}
              </span>
            </div>
          </div>

          {/* Domain Intelligence Stats */}
          <div className="p-5 bg-slate-900/40 border border-slate-800 rounded-xl space-y-3.5">
            <h3 className="font-sans font-medium text-xs tracking-wider text-slate-400 uppercase flex items-center gap-1.5">
              <Globe className="w-4 h-4 text-cyan-450" />
              SENDER DOMAIN INTEL
            </h3>

            <div className="space-y-2 text-xs">
              <div className="flex justify-between p-2 rounded bg-slate-950/40 border border-slate-850">
                <span className="text-slate-500 font-mono">Domain Age</span>
                <span className="font-mono font-bold text-white">{report.senderDomain.age}</span>
              </div>
              <div className="flex justify-between p-2 rounded bg-slate-950/40 border border-slate-850">
                <span className="text-slate-500 font-mono">Registrar</span>
                <span className="font-mono text-slate-300 truncate max-w-[120px]">{report.senderDomain.registrar}</span>
              </div>
              <div className="flex justify-between p-2 rounded bg-slate-950/40 border border-slate-850">
                <span className="text-slate-500 font-mono">Resolved IP</span>
                <span className="font-mono text-slate-300">{report.senderDomain.ipAddress}</span>
              </div>
              <div className="flex justify-between p-2 rounded bg-slate-950/40 border border-slate-850">
                <span className="text-slate-500 font-mono">Country Code</span>
                <span className="font-mono text-slate-300">{report.senderDomain.country}</span>
              </div>
              <div className="flex justify-between p-2 rounded bg-slate-950/40 border border-slate-850">
                <span className="text-slate-500 font-mono">ASN Organization</span>
                <span className="font-mono text-slate-300">{report.senderDomain.asn}</span>
              </div>
            </div>

            <div className="bg-slate-950/20 p-2.5 rounded border border-slate-850/60">
              <div className="text-[10px] font-mono text-slate-400 mb-1">Authoritative TXT Records</div>
              <div className="space-y-1">
                {report.senderDomain.txtRecords.map((rec, i) => (
                  <div key={i} className="font-mono text-[9px] text-slate-500 bg-slate-950 p-1.5 rounded truncate select-all" title={rec}>
                    {rec}
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Full SMTP Relay Flow Pathway */}
      <MailRelayFlow steps={report.headers.receivedSteps} />

      {/* Embedded Elements Audit (URLs & File attachments) */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        
        {/* URLs Table card */}
        <div className="p-6 bg-slate-900/40 border border-slate-800 rounded-xl">
          <h3 className="font-sans font-medium text-xs tracking-wider text-slate-400 uppercase flex items-center gap-1.5 mb-4">
            <Link2 className="w-4 h-4 text-cyan-400" />
            EXTRACTED URL TELEMETRY ({report.urls.length})
          </h3>

          <div className="space-y-3.5 max-h-96 overflow-y-auto pr-1">
            {report.urls.map((u, i) => {
              const isBad = u.reputation === "malicious";
              const isSus = u.reputation === "suspicious";

              return (
                <div key={i} className="p-3.5 rounded-lg bg-slate-950/50 border border-slate-800 hover:border-slate-700 transition-colors">
                  <div className="flex justify-between items-start gap-2 mb-1.5">
                    <span className="font-mono text-[10px] font-semibold text-slate-400 truncate max-w-[180px]" title={u.domain}>
                      {u.domain}
                    </span>
                    <span className={`px-2 py-0.5 rounded text-[9px] font-mono border uppercase select-none ${
                      isBad 
                        ? "bg-red-500/10 text-red-400 border-red-500/20" 
                        : isSus
                        ? "bg-amber-500/10 text-amber-400 border-amber-500/20"
                        : "bg-emerald-500/10 text-emerald-400 border-emerald-500/20"
                    }`}>
                      {u.reputation}
                    </span>
                  </div>

                  <div className="font-mono text-xs text-cyan-300 break-all select-all font-semibold p-1 bg-slate-900/40 border border-slate-850 rounded">
                    {u.url}
                  </div>

                  <div className="mt-2.5 flex flex-wrap gap-1">
                    <span className="px-1.5 py-0.5 bg-slate-900 rounded text-[9px] font-mono text-slate-500">
                      Transport: {u.hasSsl ? "HTTPS (SSL)" : "HTTP (No-SSL)"}
                    </span>
                    <span className="px-1.5 py-0.5 bg-slate-900 rounded text-[9px] font-mono text-slate-500">
                      Category: {u.category}
                    </span>
                  </div>

                  {u.indicators.length > 0 && (
                    <div className="mt-2 bg-slate-950/60 p-2 rounded border border-slate-850/60 space-y-1">
                      <div className="text-[9px] font-mono text-slate-400 uppercase tracking-widest font-bold">Threat Indicators</div>
                      {u.indicators.map((indicator, index) => (
                        <div key={index} className="text-[10px] text-slate-300 flex items-start gap-1">
                          <span className="text-rose-500 mt-0.5 font-bold">•</span>
                          <span>{indicator}</span>
                        </div>
                      ))}
                    </div>
                  )}

                  {u.redirectChain && (
                    <div className="mt-2 bg-slate-950/40 p-2 rounded border border-slate-850/40">
                      <div className="text-[9px] font-mono text-amber-400 uppercase tracking-widest font-bold">Resolved Redirect Hops</div>
                      <div className="font-mono text-[9px] text-slate-500 whitespace-nowrap overflow-x-auto">
                        {u.redirectChain.join(" ➔ ")}
                      </div>
                    </div>
                  )}
                </div>
              );
            })}

            {report.urls.length === 0 && (
              <div className="p-8 text-center text-slate-500 font-mono text-xs select-none">
                No active hyperlink paths isolated inside body section.
              </div>
            )}
          </div>
        </div>

        {/* Embedded attachments card */}
        <div className="p-6 bg-slate-900/40 border border-slate-800 rounded-xl">
          <h3 className="font-sans font-medium text-xs tracking-wider text-slate-400 uppercase flex items-center gap-1.5 mb-4">
            <Paperclip className="w-4 h-4 text-cyan-405" />
            EXTRACTED ATTACHMENT ANALYTICS ({report.attachments.length})
          </h3>

          <div className="space-y-3.5 max-h-96 overflow-y-auto pr-1">
            {report.attachments.map((a, i) => (
              <div key={i} className="p-3.5 rounded-lg bg-slate-950/50 border border-slate-800 hover:border-slate-700 transition-colors">
                <div className="flex justify-between items-start gap-2 mb-1.5">
                  <div className="min-w-0">
                    <span className="font-sans font-bold text-xs text-white truncate max-w-[190px] block" title={a.filename}>
                      {a.filename}
                    </span>
                    <span className="text-[9px] text-slate-500 font-mono block">
                      MIME: {a.mimeType} • Size: {(a.size / 1024).toFixed(1)} KB
                    </span>
                  </div>
                  <span className={`px-2 py-0.5 rounded text-[9px] font-mono border uppercase select-none ${
                    a.isSuspicious 
                      ? "bg-rose-500/10 text-rose-400 border-rose-500/20 animate-pulse" 
                      : "bg-cyan-500/10 text-cyan-400 border-cyan-500/20"
                  }`}>
                    {a.isSuspicious ? "Suspicious" : "Clean"}
                  </span>
                </div>

                {/* SHA256 Copy block */}
                <div className="mt-2.5 p-1 bg-slate-900/60 border border-slate-850 rounded flex items-center justify-between gap-1">
                  <span className="font-mono text-[9px] text-cyan-400/80 truncate max-w-[210px] select-all">
                    SHA256: {a.sha256}
                  </span>
                  <button
                    onClick={() => handleCopyHash(a.sha256, `hash_${i}`)}
                    className="p-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white transition-colors cursor-pointer"
                    title="Copy SHA256 checksum value"
                  >
                    {copiedId === `hash_${i}` ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  </button>
                </div>

                {a.indicators.length > 0 && (
                  <div className="mt-2.5 bg-slate-950/60 p-2 rounded border border-rose-500/10 space-y-1">
                    <div className="text-[9px] font-mono text-rose-400 uppercase tracking-widest font-bold">Threat Metrics Flagged</div>
                    {a.indicators.map((indicator, index) => (
                      <div key={index} className="text-[10px] text-slate-300 flex items-start gap-1">
                        <span className="text-red-500 font-bold mt-0.5">•</span>
                        <span>{indicator}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            ))}

            {report.attachments.length === 0 && (
              <div className="p-8 text-center text-slate-500 font-mono text-xs select-none">
                No active document attachments or binaries parsed.
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Aggregate Report IOC tables */}
      <IocExplorer iocs={report.iocs} />

      {/* Forensic Tabbed Console Inspector Panel */}
      <div className="border border-slate-900 bg-slate-950/20 p-5 rounded-2xl space-y-4 print:hidden">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-900 pb-3">
          <div className="flex flex-wrap gap-2 md:gap-4 select-none">
            <button
              onClick={() => setActiveForensicTab("raw")}
              className={`font-sans font-extrabold text-[11px] uppercase tracking-wider pb-2 relative transition-all cursor-pointer ${
                activeForensicTab === "raw" ? "text-cyan-400" : "text-slate-500 hover:text-slate-300"
              }`}
            >
              RAW FORENSIC STREAM
              {activeForensicTab === "raw" && (
                <div className="absolute bottom-0 left-0 w-full h-[2px] bg-cyan-500 rounded" />
              )}
            </button>
            <button
              onClick={() => setActiveForensicTab("headers")}
              className={`font-sans font-extrabold text-[11px] uppercase tracking-wider pb-2 relative transition-all cursor-pointer ${
                activeForensicTab === "headers" ? "text-cyan-400" : "text-slate-500 hover:text-slate-300"
              }`}
            >
              EXHAUSTIVE MAIL HEADERS
              {activeForensicTab === "headers" && (
                <div className="absolute bottom-0 left-0 w-full h-[2px] bg-cyan-500 rounded" />
              )}
            </button>
            <button
              onClick={() => setActiveForensicTab("iocs")}
              className={`font-sans font-extrabold text-[11px] uppercase tracking-wider pb-2 relative transition-all cursor-pointer ${
                activeForensicTab === "iocs" ? "text-cyan-400" : "text-slate-500 hover:text-slate-300"
              }`}
            >
              EXTRACTED IOC MANIFEST
              {activeForensicTab === "iocs" && (
                <div className="absolute bottom-0 left-0 w-full h-[2px] bg-cyan-500 rounded" />
              )}
            </button>
          </div>

          <button
            onClick={handleCopyForensicContent}
            className="font-mono text-[9px] font-bold tracking-wider text-slate-400 bg-slate-950 hover:bg-slate-900 border border-slate-800 rounded px-3 py-1.5 flex items-center gap-1.5 transition-all uppercase cursor-pointer self-start sm:self-auto shrink-0"
          >
            {copiedForensic ? (
              <Check className="w-3.5 h-3.5 text-emerald-400" />
            ) : (
              <Copy className="w-3.5 h-3.5" />
            )}
            <span>{getForensicBtnLabel()}</span>
          </button>
        </div>

        <div className="rounded-xl border border-slate-900 bg-slate-950/80 p-5 overflow-x-auto">
          <pre className="font-mono text-[11px] text-slate-400 leading-relaxed whitespace-pre-wrap select-all">
            {getForensicTabContent()}
          </pre>
        </div>
      </div>
    </div>
  );
}
