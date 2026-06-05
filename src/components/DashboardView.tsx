/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React from "react";
import { 
  ShieldAlert, 
  ShieldCheck, 
  FileText, 
  Link2, 
  Paperclip, 
  Clock, 
  ArrowRight, 
  Calendar,
  AlertOctagon,
  RefreshCw,
  Search,
  X,
  AlertTriangle,
  FileCode,
  ExternalLink,
  Eye,
  Cpu
} from "lucide-react";
import { SocStats } from "../types";

interface DashboardViewProps {
  stats: SocStats;
  emailsList: any[];
  onSelectEmail: (id: string) => void;
  onNavigateToUpload: () => void;
  onRefresh: () => void;
}

export default function DashboardView({ 
  stats, 
  emailsList, 
  onSelectEmail, 
  onNavigateToUpload, 
  onRefresh 
}: DashboardViewProps) {

  const [activeDetailType, setActiveDetailType] = React.useState<'highRisk' | 'suspiciousLinks' | 'scriptAttachments' | null>(null);

  // Filter high-risk emails (threatScore >= 55)
  const highRiskEmails = React.useMemo(() => {
    return emailsList.filter(eml => eml.threatScore >= 55);
  }, [emailsList]);

  // Extract suspicious/malicious URLs from the email items
  const suspiciousUrls = React.useMemo(() => {
    const list: any[] = [];
    emailsList.forEach((eml) => {
      const urls = eml.urls || [];
      urls.forEach((urlItem: any) => {
        if (urlItem.reputation === 'suspicious' || urlItem.reputation === 'malicious') {
          list.push({
            id: `${eml.id}-${urlItem.url}`,
            url: urlItem.url,
            domain: urlItem.domain,
            reputation: urlItem.reputation,
            category: urlItem.category || "General Unverified Link",
            indicators: urlItem.indicators || [],
            emailId: eml.id,
            emailSubject: eml.subject,
            sender: eml.sender,
          });
        }
      });
    });
    return list;
  }, [emailsList]);

  // Extract suspicious / script attachments from the email items
  const suspiciousAttachments = React.useMemo(() => {
    const list: any[] = [];
    const scriptExtensions = ['exe', 'bat', 'vbs', 'js', 'py', 'sh', 'zip', 'rar', 'lnk', 'xlsm', 'docm'];
    emailsList.forEach((eml) => {
      const attachments = eml.attachments || [];
      attachments.forEach((attach: any) => {
        const isScriptExt = scriptExtensions.some(ext => attach.filename?.toLowerCase().endsWith(`.${ext}`));
        if (attach.isSuspicious || isScriptExt) {
          list.push({
            id: `${eml.id}-${attach.filename || attach.sha256}`,
            filename: attach.filename || "unnamed_payload.bin",
            mimeType: attach.mimeType || "application/octet-stream",
            size: attach.size || 0,
            isSuspicious: attach.isSuspicious,
            indicators: attach.indicators || [],
            emailId: eml.id,
            emailSubject: eml.subject,
            sender: eml.sender,
          });
        }
      });
    });
    return list;
  }, [emailsList]);

  // Map severity distribution for rendering CSS graphs
  const maxDistributionValue = Math.max(
    stats.severityDistribution.critical,
    stats.severityDistribution.high,
    stats.severityDistribution.medium,
    stats.severityDistribution.low,
    1
  );

  return (
    <div className="space-y-6">
      {/* Top Welcome Panel with Action */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 p-6 bg-slate-900/40 border border-slate-800 rounded-xl">
        <div>
          <h2 className="font-sans font-bold text-lg text-white">MailRecon Hub</h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Active email threat intelligence parser and cryptographic mail integrity analysis console.
          </p>
        </div>
        <div className="flex items-center gap-2.5 shrink-0">
          <button 
            onClick={onRefresh}
            className="p-2.5 rounded-lg border border-slate-800 bg-slate-900/60 text-slate-400 hover:text-white transition-colors cursor-pointer"
            title="Refresh statistics and active lookups"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
          <button 
            onClick={onNavigateToUpload}
            className="px-4 py-2 bg-cyan-600 font-sans font-semibold text-xs text-white rounded-lg hover:bg-cyan-500 hover:shadow-lg hover:shadow-cyan-950/20 active:scale-95 transition-all cursor-pointer flex items-center gap-1.5"
          >
            <ShieldAlert className="w-4 h-4" />
            Launch Forensics Scanner
          </button>
        </div>
      </div>

      {/* Statistics Cards Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Analyzed */}
        <div className="bg-slate-900/40 border border-slate-850 p-5 rounded-xl flex items-center gap-4 hover:border-slate-800 transition-colors">
          <div className="p-3 rounded-lg bg-cyan-500/10 text-cyan-400">
            <FileText className="w-5 h-5" />
          </div>
          <div>
            <div className="text-[10px] font-mono tracking-wider text-slate-500 uppercase">Emails Analyzed</div>
            <div className="font-mono text-2xl font-bold text-white">{stats.totalAnalyzed}</div>
            <div className="text-[9px] text-slate-400 mt-0.5">Active inspection cache</div>
          </div>
        </div>

        {/* High Risk */}
        <button 
          onClick={() => setActiveDetailType('highRisk')}
          className="bg-slate-900/40 border border-slate-850 hover:border-rose-500/50 hover:bg-slate-900/60 p-5 rounded-xl flex items-center gap-4 transition-all duration-300 text-left cursor-pointer active:scale-98 select-none focus:outline-none w-full group"
        >
          <div className="p-3 rounded-lg bg-rose-500/10 text-rose-400 group-hover:scale-110 transition-transform">
            <AlertOctagon className="w-5 h-5 animate-pulse" />
          </div>
          <div>
            <div className="text-[10px] font-mono tracking-wider text-slate-300 uppercase flex items-center gap-1">
              High Risk Flagged
              <ArrowRight className="w-3.5 h-3.5 text-rose-500 opacity-0 group-hover:opacity-100 transition-opacity" />
            </div>
            <div className="font-mono text-2xl font-bold text-rose-400">{stats.highRiskCount}</div>
            <div className="text-[9px] text-slate-400 mt-0.5 group-hover:text-rose-300 transition-colors">Click to inspect malicious profiles</div>
          </div>
        </button>

        {/* Suspicious URLs */}
        <button 
          onClick={() => setActiveDetailType('suspiciousLinks')}
          className="bg-slate-900/40 border border-slate-850 hover:border-amber-500/50 hover:bg-slate-900/60 p-5 rounded-xl flex items-center gap-4 transition-all duration-300 text-left cursor-pointer active:scale-98 select-none focus:outline-none w-full group"
        >
          <div className="p-3 rounded-lg bg-amber-500/10 text-amber-400 group-hover:scale-110 transition-transform">
            <Link2 className="w-5 h-5" />
          </div>
          <div>
            <div className="text-[10px] font-mono tracking-wider text-slate-300 uppercase flex items-center gap-1">
              Suspicious Links
              <ArrowRight className="w-3.5 h-3.5 text-amber-500 opacity-0 group-hover:opacity-100 transition-opacity" />
            </div>
            <div className="font-mono text-2xl font-bold text-amber-400">{stats.suspiciousUrlsCount}</div>
            <div className="text-[9px] text-slate-400 mt-0.5 group-hover:text-amber-300 transition-colors">Click to inspect untrusted domains</div>
          </div>
        </button>

        {/* Suspicious Attachments */}
        <button 
          onClick={() => setActiveDetailType('scriptAttachments')}
          className="bg-slate-900/40 border border-slate-850 hover:border-purple-500/50 hover:bg-slate-900/60 p-5 rounded-xl flex items-center gap-4 transition-all duration-300 text-left cursor-pointer active:scale-98 select-none focus:outline-none w-full group"
        >
          <div className="p-3 rounded-lg bg-purple-500/10 text-purple-400 group-hover:scale-110 transition-transform">
            <Paperclip className="w-5 h-5" />
          </div>
          <div>
            <div className="text-[10px] font-mono tracking-wider text-slate-300 uppercase flex items-center gap-1">
              Script Attachments
              <ArrowRight className="w-3 h-3 text-purple-500 opacity-0 group-hover:opacity-100 transition-opacity" />
            </div>
            <div className="font-mono text-2xl font-bold text-purple-400">{stats.maliciousAttachmentsCount}</div>
            <div className="text-[9px] text-slate-400 mt-0.5 group-hover:text-purple-300 transition-colors">Click to inspect active binaries</div>
          </div>
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Custom Visual Interactive Chart (2 Columns wide) */}
        <div className="lg:col-span-2 bg-slate-900/40 border border-slate-800 p-5 rounded-xl flex flex-col justify-between">
          <div className="mb-4">
            <h3 className="font-sans font-medium text-xs tracking-wider text-slate-400 uppercase">
              Incident Mitigation Timeline (Heuristic Trend)
            </h3>
            <p className="text-[10px] text-slate-500">
              Fluctuations of security classification profiles logged recursively across past observation schedules.
            </p>
          </div>

          {/* Clean High Fidelity SVG Line Chart */}
          <div className="relative h-48 w-full bg-slate-950/40 rounded-lg border border-slate-900/80 p-2 flex items-end">
            {/* Grid Lines */}
            <div className="absolute inset-0 flex flex-col justify-between p-4 pointer-events-none opacity-20">
              <div className="border-b border-cyan-500 w-full" />
              <div className="border-b border-slate-700 w-full" />
              <div className="border-b border-slate-700 w-full" />
              <div className="border-b border-slate-700 w-full" />
            </div>

            {/* Custom SVG line plot & area gradient overlay */}
            <svg className="w-full h-full absolute inset-0 pt-6 pb-2 px-8" viewBox="0 0 500 130">
              <defs>
                {/* Neon Glow filters */}
                <filter id="glow-cyan" x="-20%" y="-20%" width="140%" height="140%">
                  <feGaussianBlur stdDeviation="3" result="blur" />
                  <feComposite in="SourceGraphic" in2="blur" operator="over" />
                </filter>
                <filter id="glow-rose" x="-20%" y="-20%" width="140%" height="140%">
                  <feGaussianBlur stdDeviation="3" result="blur" />
                  <feComposite in="SourceGraphic" in2="blur" operator="over" />
                </filter>
                <linearGradient id="gradient-malicious" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#ef4444" stopOpacity="0.15" />
                  <stop offset="100%" stopColor="#ef4444" stopOpacity="0.0" />
                </linearGradient>
                <linearGradient id="gradient-clean" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#22d3ee" stopOpacity="0.12" />
                  <stop offset="100%" stopColor="#22d3ee" stopOpacity="0.0" />
                </linearGradient>
              </defs>

              {/* Grid vertical alignments */}
              <line x1="10" y1="0" x2="10" y2="120" stroke="#1e293b" strokeDasharray="3" />
              <line x1="100" y1="0" x2="100" y2="120" stroke="#1e293b" strokeDasharray="3" />
              <line x1="200" y1="0" x2="200" y2="120" stroke="#1e293b" strokeDasharray="3" />
              <line x1="300" y1="0" x2="300" y2="120" stroke="#1e293b" strokeDasharray="3" />
              <line x1="400" y1="0" x2="400" y2="120" stroke="#1e293b" strokeDasharray="3" />
              <line x1="490" y1="0" x2="490" y2="120" stroke="#1e293b" strokeDasharray="3" />

              {/* AREA GRADIENTS */}
              {/* Malicious/Threat area fill */}
              <path
                d="M 10,105 C 100,75 200,90 300,60 400,20 490,45 L 490,120 L 10,120 Z"
                fill="url(#gradient-malicious)"
              />
              {/* Clean/Aligned area fill */}
              <path
                d="M 10,80 C 100,50 200,65 300,55 400,85 490,50 C 490,50 490,120 10,120 Z"
                fill="url(#gradient-clean)"
              />

              {/* PATH LINES */}
              {/* Malicious metrics line */}
              <path
                d="M 10,105 C 100,75 200,90 300,60 400,20 490,45"
                fill="none"
                stroke="#f43f5e"
                strokeWidth="2.5"
                filter="url(#glow-rose)"
              />

              {/* Clean enterprise mail line */}
              <path
                d="M 10,80 C 100,50 200,65 300,55 400,85 490,50"
                fill="none"
                stroke="#22d3ee"
                strokeWidth="2"
                filter="url(#glow-cyan)"
              />

              {/* Indicator Nodes points */}
              <circle cx="10" cy="105" r="4" fill="#f43f5e" stroke="#1e1b4b" strokeWidth="1.5" />
              <circle cx="100" cy="75" r="4" fill="#f43f5e" stroke="#1e1b4b" strokeWidth="1.5" />
              <circle cx="200" cy="90" r="4" fill="#f43f5e" stroke="#1e1b4b" strokeWidth="1.5" />
              <circle cx="300" cy="60" r="4" fill="#f43f5e" stroke="#1e1b4b" strokeWidth="1.5" />
              <circle cx="400" cy="20" r="5" fill="#f43f5e" stroke="#1e1b4b" strokeWidth="1.5" />
              <circle cx="490" cy="45" r="5" fill="#f43f5e" stroke="#1e1b4b" strokeWidth="1.5" />

              {/* X Axis Date labels inside SVG */}
              <text x="5" y="130" fill="#64748b" className="font-mono text-[9px]">28 May</text>
              <text x="90" y="130" fill="#64748b" className="font-mono text-[9px]">29 May</text>
              <text x="190" y="130" fill="#64748b" className="font-mono text-[9px]">30 May</text>
              <text x="290" y="130" fill="#64748b" className="font-mono text-[9px]">31 May</text>
              <text x="390" y="130" fill="#64748b" className="font-mono text-[9px]">01 Jun</text>
              <text x="470" y="130" fill="#64748b" className="font-mono text-[9px]">02 Jun</text>
            </svg>
          </div>

          <div className="mt-3 flex items-center gap-4 text-[10px] font-mono justify-center">
            <span className="flex items-center gap-1">
              <span className="w-2.5 h-1 bg-red-500 inline-block rounded" />
              Malicious Threats
            </span>
            <span className="flex items-center gap-1">
              <span className="w-2.5 h-1 bg-cyan-400 inline-block rounded" />
              Cryptographically Aligned
            </span>
          </div>
        </div>

        {/* Threat Severity Distribution (Bar chart) */}
        <div className="bg-slate-900/40 border border-slate-800 p-5 rounded-xl flex flex-col justify-between">
          <div>
            <h3 className="font-sans font-medium text-xs tracking-wider text-slate-400 uppercase mb-1">
              HAZARD DENSITY CATEGORIES
            </h3>
            <p className="text-[10px] text-slate-500">
              Severity metric breakdown of isolated active email payloads under current review.
            </p>
          </div>

          <div className="space-y-3.5 my-4">
            {/* Critical Row */}
            <div>
              <div className="flex justify-between text-[11px] font-mono text-slate-300 mb-1">
                <span className="flex items-center gap-1.5 font-sans font-bold text-red-400">
                  <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />
                  Critical Attack Level
                </span>
                <span>{stats.severityDistribution.critical} incidents</span>
              </div>
              <div className="h-2.5 bg-slate-950 rounded-full overflow-hidden">
                <div 
                  className="bg-red-500 h-full rounded-full transition-all duration-1000"
                  style={{ width: `${(stats.severityDistribution.critical / maxDistributionValue) * 100}%` }}
                />
              </div>
            </div>

            {/* High Row */}
            <div>
              <div className="flex justify-between text-[11px] font-mono text-slate-300 mb-1">
                <span className="flex items-center gap-1.5 font-sans font-bold text-amber-400">
                  <span className="w-2 h-2 rounded-full bg-amber-500" />
                  High Alert Level
                </span>
                <span>{stats.severityDistribution.high} incidents</span>
              </div>
              <div className="h-2.5 bg-slate-950 rounded-full overflow-hidden">
                <div 
                  className="bg-amber-500 h-full rounded-full transition-all duration-1000"
                  style={{ width: `${(stats.severityDistribution.high / maxDistributionValue) * 100}%` }}
                />
              </div>
            </div>

            {/* Medium Row */}
            <div>
              <div className="flex justify-between text-[11px] font-mono text-slate-300 mb-1">
                <span className="flex items-center gap-1.5 font-sans font-bold text-yellow-300">
                  <span className="w-2 h-2 rounded-full bg-yellow-400" />
                  Suspicious Warning Level
                </span>
                <span>{stats.severityDistribution.medium} incidents</span>
              </div>
              <div className="h-2.5 bg-slate-950 rounded-full overflow-hidden">
                <div 
                  className="bg-yellow-400 h-full rounded-full transition-all duration-1000"
                  style={{ width: `${(stats.severityDistribution.medium / maxDistributionValue) * 100}%` }}
                />
              </div>
            </div>

            {/* Low Row */}
            <div>
              <div className="flex justify-between text-[11px] font-mono text-slate-300 mb-1">
                <span className="flex items-center gap-1.5 font-sans font-bold text-cyan-400">
                  <span className="w-2 h-2 rounded-full bg-cyan-400" />
                  Low Risk Aligned
                </span>
                <span>{stats.severityDistribution.low} incidents</span>
              </div>
              <div className="h-2.5 bg-slate-950 rounded-full overflow-hidden">
                <div 
                  className="bg-cyan-500 h-full rounded-full transition-all duration-1000"
                  style={{ width: `${(stats.severityDistribution.low / maxDistributionValue) * 100}%` }}
                />
              </div>
            </div>
          </div>

          <p className="text-[10px] text-slate-400 font-mono leading-relaxed bg-slate-900/50 p-2 border border-slate-800 rounded">
            Audit score density triggers automatic quarantine workflows for files routing above index score <span className="text-red-400 font-bold">55+</span>.
          </p>
        </div>
      </div>

      {/* Recent Investigations Catalog */}
      <div className="bg-slate-900/40 border border-slate-800 rounded-xl overflow-hidden">
        <div className="p-5 border-b border-slate-800 bg-slate-900/60 flex items-center justify-between">
          <div>
            <h3 className="font-sans font-medium text-xs tracking-wider text-slate-400 uppercase">
              Recent Investigation Telemetry Log
            </h3>
            <p className="text-[10px] text-slate-500 mt-0.5">
              Parsed email threat metadata and calculated rating indices listed chronologically.
            </p>
          </div>
          <span className="text-[10px] font-mono text-slate-400 bg-slate-950 px-2 py-1 rounded">
            {emailsList.length} total indexes logged
          </span>
        </div>

        {/* Desktop View Table */}
        <div className="hidden md:block overflow-x-auto">
          <table className="w-full text-left font-sans">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-950/20 text-[10px] text-slate-500 font-mono uppercase tracking-wider">
                <th className="p-4">Sender Outbox</th>
                <th className="p-4">Incident Subject</th>
                <th className="p-4">Risk score</th>
                <th className="p-4">Payloads</th>
                <th className="p-4">Incident Timestamp</th>
                <th className="p-4 text-right">Audior Details</th>
              </tr>
            </thead>
            <tbody>
              {emailsList.map((eml) => {
                const isCritOrHigh = eml.threatScore >= 55;
                const isMed = eml.threatScore < 55 && eml.threatScore >= 25;

                return (
                  <tr 
                    key={eml.id} 
                    className="border-b border-slate-850 hover:bg-slate-900/10 transition-colors select-none"
                  >
                    {/* Sender */}
                    <td className="p-4 max-w-xs truncate font-mono text-xs text-slate-300">
                      <div>{eml.sender}</div>
                      <div className="text-[10px] text-slate-500 mt-0.5 truncate uppercase">To: {eml.recipient}</div>
                    </td>

                    {/* Subject */}
                    <td className="p-4 font-sans text-xs font-semibold text-white max-w-xs truncate">
                      {eml.subject}
                    </td>

                    {/* Threat Index */}
                    <td className="p-4 whitespace-nowrap">
                      <div className="flex items-center gap-2">
                        <span className={`w-2.5 h-2.5 rounded-full ${isCritOrHigh ? "bg-red-500" : isMed ? "bg-amber-500" : "bg-cyan-400"}`} />
                        <span className={`font-mono font-bold text-xs ${isCritOrHigh ? "text-red-400" : isMed ? "text-amber-400" : "text-cyan-400"}`}>
                          {eml.threatScore}/100 
                        </span>
                        <span className="text-[10px] text-slate-500 font-mono capitalize">({eml.threatLevel})</span>
                      </div>
                    </td>

                    {/* Payloads counts */}
                    <td className="p-4 whitespace-nowrap">
                      <div className="flex items-center gap-2.5 text-slate-400 text-xs font-mono">
                        <span className={eml.attachmentsCount > 0 ? "text-purple-400 font-semibold" : ""}>
                          📎 {eml.attachmentsCount}
                        </span>
                        <span className={eml.urlsCount > 0 ? "text-amber-400 font-semibold" : ""}>
                          🔗 {eml.urlsCount}
                        </span>
                      </div>
                    </td>

                    {/* Timestamp */}
                    <td className="p-4 whitespace-nowrap text-xs text-slate-400 font-mono">
                      <div className="flex items-center gap-1.5">
                        <Calendar className="w-3.5 h-3.5 text-slate-500" />
                        {new Date(eml.timestamp).toLocaleString("en-US", {
                          month: "short",
                          day: "numeric",
                          hour: "2-digit",
                          minute: "2-digit"
                        })}
                      </div>
                    </td>

                    {/* Navigation */}
                    <td className="p-4 text-right whitespace-nowrap">
                      <button
                        onClick={() => onSelectEmail(eml.id)}
                        className="p-1 px-3 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white font-mono text-[10px] flex items-center inline-flex gap-1.5 transition-colors cursor-pointer"
                      >
                        <span>Investigate</span>
                        <ArrowRight className="w-3 h-3" />
                      </button>
                    </td>
                  </tr>
                );
              })}

              {emailsList.length === 0 && (
                <tr>
                  <td colSpan={6} className="p-12 text-center text-slate-500 font-mono text-xs">
                    Please submit email EML dumps to begin compiling threat telemetry.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Mobile View Cards List */}
        <div className="block md:hidden divide-y divide-slate-800/60 bg-slate-905/30">
          {emailsList.map((eml) => {
            const isCritOrHigh = eml.threatScore >= 55;
            const isMed = eml.threatScore < 55 && eml.threatScore >= 25;

            return (
              <div key={eml.id} className="p-4 space-y-3">
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono text-[10px] text-slate-400 block truncate max-w-[170px]" title={eml.sender}>
                    From: {eml.sender}
                  </span>
                  <div className="flex items-center gap-1.5 shrink-0">
                    <span className={`w-2 h-2 rounded-full ${isCritOrHigh ? "bg-red-500" : isMed ? "bg-amber-500" : "bg-cyan-400"}`} />
                    <span className={`font-mono font-bold text-xs ${isCritOrHigh ? "text-red-400" : isMed ? "text-amber-400" : "text-cyan-400"}`}>
                      {eml.threatScore}/100
                    </span>
                  </div>
                </div>

                <div>
                  <h4 className="font-sans text-xs font-semibold text-white leading-snug">
                    {eml.subject}
                  </h4>
                  <div className="text-[10px] text-slate-500 font-mono mt-1">To: {eml.recipient}</div>
                </div>

                <div className="flex items-center justify-between pt-2.5 border-t border-slate-900/40 text-[11px] font-mono">
                  <div className="flex items-center gap-3 text-slate-400">
                    <span className={eml.attachmentsCount > 0 ? "text-purple-400 font-semibold" : ""}>
                      📎 {eml.attachmentsCount}
                    </span>
                    <span className={eml.urlsCount > 0 ? "text-amber-400 font-semibold" : ""}>
                      🔗 {eml.urlsCount}
                    </span>
                    <span className="text-slate-500 pl-1 text-[10px]">
                      {new Date(eml.timestamp).toLocaleDateString("en-US", { month: "short", day: "numeric" })}
                    </span>
                  </div>

                  <button
                    onClick={() => onSelectEmail(eml.id)}
                    className="p-1 px-3 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white font-mono text-[10px] flex items-center gap-1 transition-colors cursor-pointer"
                  >
                    <span>Investigate</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            );
          })}

          {emailsList.length === 0 && (
            <div className="p-8 text-center text-slate-500 font-mono text-xs">
              Please submit email EML dumps to begin compiling threat telemetry.
            </div>
          )}
        </div>
      </div>

      {/* Interactive Detail Modal Backdrop */}
      {activeDetailType && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-md animate-fade-in">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-3xl w-full max-h-[85vh] flex flex-col shadow-2xl overflow-hidden shadow-cyan-950/20">
            {/* Modal Header */}
            <div className="p-5 border-b border-slate-800 flex items-center justify-between bg-slate-950/40 select-none">
              <div className="flex items-center gap-2.5">
                {activeDetailType === "highRisk" && (
                  <div className="p-2 rounded bg-rose-500/10 text-rose-400">
                    <AlertOctagon className="w-5 h-5" />
                  </div>
                )}
                {activeDetailType === "suspiciousLinks" && (
                  <div className="p-2 rounded bg-amber-500/10 text-amber-400">
                    <Link2 className="w-5 h-5" />
                  </div>
                )}
                {activeDetailType === "scriptAttachments" && (
                  <div className="p-2 rounded bg-purple-500/10 text-purple-400">
                    <Paperclip className="w-5 h-5" />
                  </div>
                )}
                <div>
                  <h3 className="font-sans font-bold text-sm text-white uppercase tracking-wider">
                    {activeDetailType === "highRisk" && "High-Risk Threat Indicators"}
                    {activeDetailType === "suspiciousLinks" && "Isolated Suspicious/Malicious Links"}
                    {activeDetailType === "scriptAttachments" && "Isolated Script/Binary Attachments"}
                  </h3>
                  <p className="text-[10px] text-slate-400 mt-0.5">
                    {activeDetailType === "highRisk" && `Identified ${highRiskEmails.length} mail vectors exceeding alarm threshold score (55+)`}
                    {activeDetailType === "suspiciousLinks" && `Extracted ${suspiciousUrls.length} links with poor domain trust rankings`}
                    {activeDetailType === "scriptAttachments" && `Isolated ${suspiciousAttachments.length} executable, system launch or script elements`}
                  </p>
                </div>
              </div>
              <button
                onClick={() => setActiveDetailType(null)}
                className="p-1.5 rounded-lg border border-slate-800 bg-slate-900 text-slate-400 hover:text-white transition-colors cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Modal Content */}
            <div className="p-6 overflow-y-auto space-y-4 flex-1">
              {/* Type: HIGH RISK MAIL LIST */}
              {activeDetailType === "highRisk" && (
                <div className="space-y-4">
                  {highRiskEmails.length === 0 ? (
                    <div className="text-center py-12 text-slate-500 font-mono text-xs">
                      No high-risk emails flagged in the active index yet.
                    </div>
                  ) : (
                    highRiskEmails.map((eml) => (
                      <div 
                        key={eml.id} 
                        className="bg-slate-950/40 border border-slate-850 hover:border-slate-800 p-4 rounded-xl space-y-3 transition-colors text-left"
                      >
                        <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-4">
                          <div className="space-y-1">
                            <h4 className="font-sans font-bold text-xs text-white leading-snug">
                              {eml.subject}
                            </h4>
                            <div className="font-mono text-[10px] text-slate-400">
                              From: {eml.sender}
                            </div>
                          </div>
                          <div className="flex items-center gap-1.5 whitespace-nowrap shrink-0">
                            <span className="text-[9px] font-mono text-slate-500 uppercase">Risk Level:</span>
                            <span className="font-mono text-xs font-bold text-rose-400 px-2.5 py-0.5 rounded bg-rose-500/10 border border-rose-500/20">
                              {eml.threatScore}/100 ({eml.threatLevel})
                            </span>
                          </div>
                        </div>

                        {eml.aiExplanation ? (
                          <div className="bg-slate-950/60 border border-slate-900 rounded p-3 text-[11px] font-sans leading-relaxed text-slate-300">
                            <div className="text-[10px] font-mono uppercase tracking-wider text-rose-400 mb-1 font-semibold flex items-center gap-1">
                              <AlertTriangle className="w-3.5 h-3.5" /> Verdict Summary
                            </div>
                            <p className="font-medium text-slate-100">{eml.aiExplanation.verdict}</p>
                            
                            {eml.aiExplanation.reasons && eml.aiExplanation.reasons.length > 0 && (
                              <div className="mt-2 pt-2 border-t border-slate-900 space-y-1">
                                <span className="font-mono text-[9px] text-slate-500 uppercase tracking-wide">Threat Indicators Detected:</span>
                                <ul className="list-disc pl-4 space-y-1 text-slate-300 mt-1">
                                  {eml.aiExplanation.reasons.map((reason: string, rIdx: number) => (
                                    <li key={rIdx}>{reason}</li>
                                  ))}
                                </ul>
                              </div>
                            )}
                          </div>
                        ) : (
                          <div className="text-[10px] italic text-slate-500 bg-slate-950/60 p-2 rounded">
                            No automatic reasons list generated during simulation.
                          </div>
                        )}

                        <div className="flex justify-end pt-1">
                          <button
                            onClick={() => {
                              setActiveDetailType(null);
                              onSelectEmail(eml.id);
                            }}
                            className="px-3.5 py-1.5 bg-slate-850 hover:bg-slate-700 text-slate-200 hover:text-white rounded font-mono text-[10px] flex items-center gap-1.5 transition-colors cursor-pointer border border-slate-750"
                          >
                            <Eye className="w-3.5 h-3.0 text-cyan-400" />
                            <span>Inspect Target Core View</span>
                          </button>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              )}

              {/* Type: SUSPICIOUS URLS */}
              {activeDetailType === "suspiciousLinks" && (
                <div className="space-y-4">
                  {suspiciousUrls.length === 0 ? (
                    <div className="text-center py-12 text-slate-500 font-mono text-xs">
                      No malicious or suspicious links extracted in the current database logs.
                    </div>
                  ) : (
                    suspiciousUrls.map((urlItem) => (
                      <div 
                        key={urlItem.id} 
                        className="bg-slate-950/40 border border-slate-850 hover:border-slate-800 p-4 rounded-xl space-y-3 transition-colors text-left"
                      >
                        <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-4">
                          <div className="space-y-1.5 flex-1 min-w-0">
                            <span className="font-mono text-[9px] text-slate-500 uppercase tracking-wider block">Target Host Connection URL</span>
                            <div className="font-mono text-[11px] text-amber-400 break-all bg-slate-950/70 p-2 rounded-lg border border-slate-900/80 flex items-center gap-2">
                              <ExternalLink className="w-3.5 h-3.5 text-amber-500 shrink-0" />
                              <span className="truncate max-w-[500px]">{urlItem.url}</span>
                            </div>
                          </div>
                          <span className={`font-mono text-[10px] font-bold px-2 py-0.5 rounded capitalize shrink-0 border h-fit ${
                            urlItem.reputation === "malicious" 
                              ? "text-red-400 bg-red-500/10 border-red-500/20" 
                              : "text-amber-400 bg-amber-500/10 border-amber-500/20"
                          }`}>
                            {urlItem.reputation}
                          </span>
                        </div>

                        <div className="bg-slate-950/60 p-3 rounded space-y-1.5 font-sans text-left">
                          <div className="flex justify-between items-center text-[10px] font-mono border-b border-slate-900 pb-1">
                            <span className="text-slate-400 uppercase">Detection Group</span>
                            <span className="text-slate-200">{urlItem.category}</span>
                          </div>

                          {urlItem.indicators && urlItem.indicators.length > 0 && (
                            <div className="pt-1.5 space-y-1">
                              <span className="font-mono text-[9px] text-slate-500 uppercase tracking-wide block">Threat Warnings:</span>
                              <div className="flex flex-wrap gap-1.5 mt-1">
                                {urlItem.indicators.map((ind: string, idx: number) => (
                                  <span key={idx} className="font-mono text-[9px] bg-slate-900 text-slate-300 border border-slate-800 px-2 py-0.5 rounded-full">
                                    ⚠️ {ind}
                                  </span>
                                ))}
                              </div>
                            </div>
                          )}
                        </div>

                        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 pt-2 border-t border-slate-950 border-dashed">
                          <span className="font-sans text-[10px] text-slate-400 truncate max-w-sm">
                            Found in: <span className="font-semibold text-slate-200">"{urlItem.emailSubject}"</span>
                          </span>
                          <button
                            onClick={() => {
                              setActiveDetailType(null);
                              onSelectEmail(urlItem.emailId);
                            }}
                            className="px-3.5 py-1.5 bg-slate-850 hover:bg-slate-700 text-slate-200 hover:text-white rounded font-mono text-[10px] flex items-center gap-1.5 transition-colors cursor-pointer border border-slate-750 self-end sm:self-auto"
                          >
                            <Eye className="w-3.5 h-3.5 text-cyan-400" />
                            <span>Investigate Mail Origin</span>
                          </button>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              )}

              {/* Type: SCRIPT ATTACHMENTS */}
              {activeDetailType === "scriptAttachments" && (
                <div className="space-y-4">
                  {suspiciousAttachments.length === 0 ? (
                    <div className="text-center py-12 text-slate-500 font-mono text-xs">
                      No script files or suspicious attachments tracked in current index list.
                    </div>
                  ) : (
                    suspiciousAttachments.map((attach) => (
                      <div 
                        key={attach.id} 
                        className="bg-slate-950/40 border border-slate-850 hover:border-slate-800 p-4 rounded-xl space-y-3 transition-colors text-left"
                      >
                        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
                          <div className="flex items-center gap-3">
                            <div className="p-2.5 rounded-lg bg-purple-500/10 text-purple-400 border border-purple-500/10 shrink-0">
                              <FileCode className="w-5 h-5 animate-pulse" />
                            </div>
                            <div>
                              <h4 className="font-sans font-bold text-xs text-white leading-snug">
                                {attach.filename}
                              </h4>
                              <div className="font-mono text-[10px] text-slate-500">
                                {attach.mimeType} • {attach.size ? `${(attach.size / 1024).toFixed(1)} KB` : "N/A"}
                              </div>
                            </div>
                          </div>
                          
                          <span className="font-mono text-[9px] bg-purple-500/10 text-purple-400 border border-purple-500/20 px-2 py-0.5 rounded uppercase font-semibold h-fit w-fit">
                            Sandbox Triggered
                          </span>
                        </div>

                        {attach.indicators && attach.indicators.length > 0 && (
                          <div className="bg-slate-950/60 p-3 rounded font-sans text-[11px] leading-relaxed text-slate-300 text-left">
                            <span className="font-mono text-[9px] text-slate-500 uppercase tracking-wide block mb-1">Static Forensic Indicators:</span>
                            <ul className="list-disc pl-4 space-y-1">
                              {attach.indicators.map((ind: string, idx: number) => (
                                <li key={idx} className="text-slate-300">
                                  {ind}
                                </li>
                              ))}
                            </ul>
                          </div>
                        )}

                        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 pt-2 border-t border-slate-950 border-dashed">
                          <span className="font-sans text-[10px] text-slate-400 truncate max-w-sm">
                            Extracted from: <span className="font-semibold text-slate-200">"{attach.emailSubject}"</span>
                          </span>
                          <button
                            onClick={() => {
                              setActiveDetailType(null);
                              onSelectEmail(attach.emailId);
                            }}
                            className="px-3.5 py-1.5 bg-slate-850 hover:bg-slate-700 text-slate-200 hover:text-white rounded font-mono text-[10px] flex items-center gap-1.5 transition-colors cursor-pointer border border-slate-750 self-end sm:self-auto"
                          >
                            <Eye className="w-3.5 h-3.5 text-cyan-400" />
                            <span>Investigate Mail Origin</span>
                          </button>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              )}
            </div>

            {/* Modal Footer */}
            <div className="p-4 border-t border-slate-800 bg-slate-950/20 flex justify-end">
              <button
                onClick={() => setActiveDetailType(null)}
                className="px-4 py-2 rounded-lg border border-slate-800 bg-slate-900 text-slate-300 hover:text-white font-sans font-semibold text-xs transition-colors cursor-pointer"
              >
                Close Summary Hub
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
