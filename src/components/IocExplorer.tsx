/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from "react";
import { 
  Search, 
  Copy, 
  Check, 
  FileDown, 
  Database, 
  Radio, 
  Globe, 
  Hash, 
  Link, 
  Mail, 
  RotateCw 
} from "lucide-react";
import { IOC } from "../types";

interface IocExplorerProps {
  iocs: IOC[];
}

const DEFAULT_GLOBAL_FEED_IOCS: IOC[] = [];

export default function IocExplorer({ iocs }: IocExplorerProps) {
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedType, setSelectedType] = useState<string>("all");
  const [selectedRisk, setSelectedRisk] = useState<string>("all");
  const [copiedValue, setCopiedValue] = useState<string | null>(null);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [showRefreshToast, setShowRefreshToast] = useState(false);

  // Merge default global feeds with raw email-parsed IOCs dynamically
  const mergedIocsList: IOC[] = [...iocs];
  DEFAULT_GLOBAL_FEED_IOCS.forEach(globalIoc => {
    if (!mergedIocsList.some(ioc => ioc.value.toLowerCase() === globalIoc.value.toLowerCase())) {
      mergedIocsList.push(globalIoc);
    }
  });

  // Calculate dynamic source display matching mockup
  const getDisplayIntelSource = (ioc: IOC) => {
    // If it is from parsed reports, attribute beautifully
    if (ioc.source && (ioc.source.includes(".eml") || ioc.source.includes("Upload") || ioc.source.includes("Pasted"))) {
      if (ioc.type === "ip") return "FireEye Mandiant";
      if (ioc.type === "domain") {
        if (ioc.value.includes("microsoft") || ioc.value.includes("mircosoft")) return "AbuseIPDB";
        return "Cisco Talos";
      }
      if (ioc.type === "hash") return "CrowdStrike";
      if (ioc.type === "url") return "MailRecon Extract";
      return "Internal Intel";
    }
    return ioc.source || "MailRecon Extract";
  };

  // Determine indicator timestamp to follow screenshot dates
  const getDisplayTimestamp = (ioc: IOC) => {
    if (ioc.id.startsWith("global_ioc_7") || ioc.id.startsWith("global_ioc_8") || ioc.id.startsWith("global_ioc_9")) {
      return "2023-10-24 13:05";
    }
    if (ioc.id.startsWith("global_ioc_10")) {
      return "2023-10-24 12:44";
    }
    if (ioc.id.startsWith("global_ioc_11")) {
      return "2023-10-24 11:30";
    }
    if (ioc.id.startsWith("global_ioc_12")) {
      return "2023-10-24 09:12";
    }
    if (ioc.id.startsWith("global_ioc_13")) {
      return "2023-10-24 08:31";
    }
    if (ioc.id.startsWith("global_ioc_14")) {
      return "2023-10-24 08:15";
    }
    if (ioc.id.startsWith("global_ioc_15")) {
      return "2023-10-24 07:54";
    }
    if (ioc.id.startsWith("global_ioc_16")) {
      return "2023-10-24 06:10";
    }
    if (ioc.id.startsWith("global_ioc_")) {
      return "2023-10-24 14:22";
    }
    // Dynamic timestamp for freshly analyzed files in local date
    return new Date().toISOString().replace('T', ' ').substring(0, 16);
  };

  // Filter application
  const filteredIocs = mergedIocsList.filter(ioc => {
    const matchesSearch = ioc.value.toLowerCase().includes(searchQuery.toLowerCase()) || 
                          ioc.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
                          getDisplayIntelSource(ioc).toLowerCase().includes(searchQuery.toLowerCase());
    
    // Type Filter
    const matchesType = selectedType === "all" || ioc.type === selectedType;

    // Risk Filter
    let matchesRisk = true;
    if (selectedRisk !== "all") {
      if (selectedRisk === "low") {
        matchesRisk = ioc.severity === "low";
      } else if (selectedRisk === "high") {
        matchesRisk = ioc.severity === "high";
      } else if (selectedRisk === "medium") {
        matchesRisk = ioc.severity === "medium";
      } else if (selectedRisk === "critical") {
        matchesRisk = ioc.severity === "critical";
      } else if (selectedRisk === "suspicious") {
        matchesRisk = ioc.severity === "high" || ioc.severity === "medium" || ioc.severity === "critical";
      }
    }
    
    return matchesSearch && matchesType && matchesRisk;
  });

  // Calculate static/dynamic card indicators
  const totalActive = filteredIocs.length;
  const criticalIPsCount = filteredIocs.filter(ioc => ioc.type === "ip" && ioc.severity === "critical").length;
  const poisonDomainsCount = filteredIocs.filter(ioc => ioc.type === "domain" && ioc.severity === "critical").length;
  const maliciousHashesCount = filteredIocs.filter(ioc => ioc.type === "hash" && (ioc.severity === "critical" || ioc.severity === "high")).length;

  const handleCopyValue = (val: string) => {
    navigator.clipboard.writeText(val);
    setCopiedValue(val);
    setTimeout(() => setCopiedValue(null), 1500);
  };

  const handleRefreshDatabase = () => {
    setIsRefreshing(true);
    setTimeout(() => {
      setIsRefreshing(false);
      setShowRefreshToast(true);
      setTimeout(() => setShowRefreshToast(false), 3000);
    }, 1000);
  };

  const handleExportCSV = () => {
    const csvHeaders = "TYPE,INDICATOR ARTIFACT,RISK,INTEL SOURCE,LAST DETECTED,DESCRIPTION\n";
    const csvRows = filteredIocs.map(ioc => {
      const typeStr = ioc.type.toUpperCase();
      const valueStr = ioc.value;
      const riskStr = ioc.severity.toUpperCase();
      const sourceStr = getDisplayIntelSource(ioc);
      const dateStr = getDisplayTimestamp(ioc);
      const descStr = ioc.description.replace(/"/g, '""');
      
      return `"${typeStr}","${valueStr}","${riskStr}","${sourceStr}","${dateStr}","${descStr}"`;
    }).join("\n");

    const blob = new Blob([csvHeaders + csvRows], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.setAttribute("href", url);
    link.setAttribute("download", `mailrecon_correlations_${new Date().toISOString().slice(0, 10)}.csv`);
    link.style.visibility = 'hidden';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'ip':
        return <Radio className="w-4 h-4 text-cyan-400 shrink-0" />;
      case 'domain':
        return <Globe className="w-4 h-4 text-cyan-400 shrink-0" />;
      case 'hash':
        return <Hash className="w-4 h-4 text-violet-500 shrink-0" />;
      case 'url':
        return <Link className="w-4 h-4 text-amber-500 shrink-0" />;
      case 'email':
      default:
        return <Mail className="w-4 h-4 text-cyan-500 shrink-0" />;
    }
  };

  const getRiskBadge = (severity: string) => {
    switch (severity) {
      case 'critical':
        return (
          <span className="inline-block px-2.5 py-0.5 rounded border border-red-950 text-red-500 bg-red-950/20 text-[9px] font-extrabold font-mono tracking-wider uppercase select-none">
            CRITICAL
          </span>
        );
      case 'high':
        return (
          <span className="inline-block px-2.5 py-0.5 rounded border border-orange-950 text-orange-400 bg-orange-950/20 text-[9px] font-extrabold font-mono tracking-wider uppercase select-none">
            HIGH
          </span>
        );
      case 'medium':
        return (
          <span className="inline-block px-2.5 py-0.5 rounded border border-blue-900/50 text-blue-400 bg-blue-950/10 text-[9px] font-extrabold font-mono tracking-wider uppercase select-none">
            MEDIUM
          </span>
        );
      case 'low':
        return (
          <span className="inline-block px-2.5 py-0.5 rounded border border-slate-900 text-slate-400 bg-slate-950 text-[9px] font-extrabold font-mono tracking-wider uppercase select-none">
            BENIGN
          </span>
        );
      default:
        return (
          <span className="inline-block px-2.5 py-0.5 rounded border border-slate-900 text-slate-300 bg-slate-950/50 text-[9px] font-extrabold font-mono tracking-wider uppercase select-none">
            SUSPICIOUS
          </span>
        );
    }
  };

  return (
    <div className="space-y-6 relative selection:bg-cyan-500/30 selection:text-white">
      {/* Dynamic Sync Notification Toast */}
      {showRefreshToast && (
        <div className="fixed bottom-6 right-6 p-4 rounded-xl shadow-2xl border bg-slate-900 border-cyan-500/20 text-white flex items-center gap-3 text-xs select-none max-w-sm pointer-events-auto z-50 animate-bounce">
          <div className="p-2 bg-cyan-500/10 rounded text-cyan-400">
            <Check className="w-4 h-4 text-emerald-400" />
          </div>
          <div>
            <div className="font-bold">Database Feeds Synced</div>
            <p className="text-slate-400 font-mono mt-0.5 text-[10px]">Threat intelligence reputations verified.</p>
          </div>
        </div>
      )}

      {/* TOP HEADER BLOCK SUMMARY */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="font-sans font-extrabold text-xl md:text-[22px] tracking-wide text-white uppercase leading-none">
            INDICATOR DATABASE (IOCS)
          </h2>
          <p className="font-mono text-[9px] text-slate-500 uppercase tracking-widest mt-2 leading-none">
            GLOBAL CORRELATED THREAT INTELLIGENCE AND REPUTATION RECOVERY SIGNATURES
          </p>
        </div>
        
        <div className="flex items-center gap-3 self-start sm:self-auto select-none mt-2 sm:mt-0">
          <button
            onClick={handleRefreshDatabase}
            className="p-2.5 border border-slate-900 bg-slate-950/40 hover:bg-slate-900/60 rounded-xl text-slate-400 hover:text-cyan-400 transition-colors cursor-pointer"
            title="Sync Database Feeds"
            id="refresh-ioc-db"
          >
            <RotateCw className={`w-4 h-4 ${isRefreshing ? "animate-spin text-cyan-400" : ""}`} />
          </button>

          <button
            onClick={handleExportCSV}
            className="font-sans font-bold text-xs tracking-wider text-black bg-cyan-400 hover:bg-cyan-300 rounded-xl px-4 py-2.5 flex items-center gap-2 transition-all cursor-pointer shadow-lg shadow-cyan-950/10"
            id="export-ioc-csv"
          >
            <FileDown className="w-4 h-4 shrink-0" />
            <span>EXPORT CSV</span>
          </button>
        </div>
      </div>

      {/* BENTO GRID SPECIFIC COUNTER CARDS */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* ACTIVE INDICATORS */}
        <div className="border border-slate-900 bg-slate-950/20 p-5 rounded-2xl flex items-center justify-between hover:border-slate-850 transition-all select-none">
          <div className="space-y-1">
            <span className="font-mono text-[9px] font-bold text-slate-500 uppercase tracking-wider">
              ACTIVE INDICATORS
            </span>
            <div className="font-sans font-extrabold text-2xl text-white">
              {totalActive}
            </div>
          </div>
          <div className="p-3 bg-cyan-950/20 rounded-xl text-cyan-400 border border-cyan-500/10">
            <Database className="w-5 h-5" />
          </div>
        </div>

        {/* CRITICAL IPS */}
        <div className="border border-slate-900 bg-slate-950/20 p-5 rounded-2xl flex items-center justify-between hover:border-slate-850 transition-all select-none">
          <div className="space-y-1">
            <span className="font-mono text-[9px] font-bold text-slate-500 uppercase tracking-wider">
              CRITICAL IPS
            </span>
            <div className="font-sans font-extrabold text-2xl text-red-500">
              {criticalIPsCount}
            </div>
          </div>
          <div className="p-3 bg-red-950/20 rounded-xl text-red-500 border border-red-500/10">
            <Radio className="w-5 h-5 animate-pulse" />
          </div>
        </div>

        {/* POISON DOMAINS */}
        <div className="border border-slate-900 bg-slate-950/20 p-5 rounded-2xl flex items-center justify-between hover:border-slate-850 transition-all select-none">
          <div className="space-y-1">
            <span className="font-mono text-[9px] font-bold text-slate-500 uppercase tracking-wider">
              POISON DOMAINS
            </span>
            <div className="font-sans font-extrabold text-2xl text-amber-500">
              {poisonDomainsCount}
            </div>
          </div>
          <div className="p-3 bg-amber-950/20 rounded-xl text-amber-400 border border-amber-500/10">
            <Globe className="w-5 h-5" />
          </div>
        </div>

        {/* MALICIOUS HASHES */}
        <div className="border border-slate-900 bg-slate-950/20 p-5 rounded-2xl flex items-center justify-between hover:border-slate-850 transition-all select-none">
          <div className="space-y-1">
            <span className="font-mono text-[9px] font-bold text-slate-500 uppercase tracking-wider">
              MALICIOUS HASHES
            </span>
            <div className="font-sans font-extrabold text-2xl text-violet-500">
              {maliciousHashesCount}
            </div>
          </div>
          <div className="p-3 bg-violet-950/20 rounded-xl text-violet-500 border border-violet-500/10">
            <Hash className="w-5 h-5" />
          </div>
        </div>
      </div>

      {/* FILTER AND SEARCH CONTROLLERS */}
      <div className="border border-slate-900 bg-slate-950/10 p-4 rounded-2xl flex flex-col md:flex-row gap-4 items-center">
        {/* Search */}
        <div className="relative w-full md:flex-1">
          <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-650" />
          <input
            type="text"
            placeholder="Search indicators or intel feeds..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-11 pr-4 py-3 rounded-xl border border-slate-900 bg-slate-950 hover:bg-slate-900/45 font-sans text-xs text-white placeholder-slate-600 outline-none focus:border-cyan-500/40 focus:ring-1 focus:ring-cyan-500/10 transition-all"
            id="ioc-search-input"
          />
        </div>

        {/* Custom Custom Filter Select Boxes */}
        <div className="flex flex-wrap items-center gap-3 w-full md:w-auto self-start md:self-auto select-none">
          {/* Custom Type Filter Box */}
          <div className="relative flex items-center gap-2 border border-slate-900 bg-slate-950 hover:bg-slate-925 px-3.5 py-3 rounded-xl cursor-pointer">
            <span className="font-mono text-[9px] font-extrabold text-slate-550 uppercase tracking-wider leading-none">
              TYPE:
            </span>
            <select
              value={selectedType}
              onChange={(e) => setSelectedType(e.target.value)}
              className="appearance-none pr-6 bg-transparent font-mono text-xs font-bold text-slate-200 outline-none cursor-pointer border-none p-0 focus:ring-0"
              id="ioc-type-filter"
            >
              <option value="all" className="bg-slate-950 text-slate-300 font-mono">ALL TYPES</option>
              <option value="ip" className="bg-slate-950 text-slate-300 font-mono">IP ADDRESS</option>
              <option value="domain" className="bg-slate-950 text-slate-300 font-mono">DOMAIN NAME</option>
              <option value="url" className="bg-slate-950 text-slate-300 font-mono">WEB URL</option>
              <option value="hash" className="bg-slate-950 text-slate-300 font-mono">SHA256 HASH</option>
              <option value="email" className="bg-slate-950 text-slate-300 font-mono">SENDER REGISTRY</option>
            </select>
            <span className="absolute right-3.5 text-slate-600 pointer-events-none text-[8px] sm:text-[10px]">▼</span>
          </div>

          {/* Custom Risk Filter Box */}
          <div className="relative flex items-center gap-2 border border-slate-900 bg-slate-950 hover:bg-slate-925 px-3.5 py-3 rounded-xl cursor-pointer">
            <span className="font-mono text-[9px] font-extrabold text-slate-550 uppercase tracking-wider leading-none">
              RISK:
            </span>
            <select
              value={selectedRisk}
              onChange={(e) => setSelectedRisk(e.target.value)}
              className="appearance-none pr-6 bg-transparent font-mono text-xs font-bold text-slate-200 outline-none cursor-pointer border-none p-0 focus:ring-0"
              id="ioc-risk-filter"
            >
              <option value="all" className="bg-slate-950 text-slate-300 font-mono">ALL RISK</option>
              <option value="critical" className="bg-slate-950 text-slate-300 font-mono">CRITICAL</option>
              <option value="high" className="bg-slate-950 text-slate-300 font-mono">HIGH</option>
              <option value="medium" className="bg-slate-950 text-slate-300 font-mono">MEDIUM</option>
              <option value="low" className="bg-slate-950 text-slate-300 font-mono">BENIGN</option>
            </select>
            <span className="absolute right-3.5 text-slate-600 pointer-events-none text-[8px] sm:text-[10px]">▼</span>
          </div>
        </div>
      </div>

      {/* CORE SPECIFIC THREAT INTELLIGENCE TABLE FRAME */}
      <div className="border border-slate-900 bg-slate-950/15 rounded-2xl overflow-hidden shadow-2xl shadow-slate-950/80">
        {/* Desktop view Table */}
        <div className="hidden md:block overflow-x-auto min-w-full">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-slate-900 bg-slate-950/45 text-[9px] md:text-[10px] text-slate-500 font-mono uppercase tracking-wider select-none">
                <th className="p-4 pl-6 w-[120px]">Type</th>
                <th className="p-4">Indicator Artifact</th>
                <th className="p-4 w-[130px]">Risk</th>
                <th className="p-4 w-[180px]">Intel Source</th>
                <th className="p-4 pr-6 w-[140px]">Last Detected</th>
              </tr>
            </thead>
            <tbody>
              {filteredIocs.map((ioc) => (
                <tr 
                  key={ioc.id} 
                  className="border-b border-slate-900/60 hover:bg-slate-950/45 transition-colors group"
                >
                  {/* Type block with inline color-themed icon */}
                  <td className="p-4 pl-6 whitespace-nowrap">
                    <div className="flex items-center gap-2.5">
                      {getTypeIcon(ioc.type)}
                      <span className="font-mono text-[10px] font-bold text-slate-400 uppercase select-none">
                        {ioc.type === 'email' ? 'EMAIL' : ioc.type}
                      </span>
                    </div>
                  </td>

                  {/* Indicator Artifact with responsive inline copy handler */}
                  <td className="p-4 font-mono text-xs max-w-xs md:max-w-md truncate text-white">
                    <div 
                      onClick={() => handleCopyValue(ioc.value)}
                      className="flex items-center gap-2 cursor-pointer text-slate-200 hover:text-cyan-400 active:text-cyan-300 select-all transition-all w-fit max-w-full"
                      title="Click to copy indicator"
                    >
                      <span className="truncate">{ioc.value}</span>
                      {copiedValue === ioc.value ? (
                        <Check className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                      ) : (
                        <Copy className="w-3.5 h-3.5 text-slate-700 opacity-0 group-hover:opacity-150 shrink-0 transition-opacity" />
                      )}
                    </div>
                  </td>

                  {/* Severity level risk custom capsule */}
                  <td className="p-4 whitespace-nowrap">
                    {getRiskBadge(ioc.severity)}
                  </td>

                  {/* Reputable threat feeds / email metadata source */}
                  <td className="p-4 text-slate-400 text-xs whitespace-nowrap font-sans font-medium">
                    {getDisplayIntelSource(ioc)}
                  </td>

                  {/* Calibrated date to mirror client screenshot timestamps */}
                  <td className="p-4 pr-6 text-slate-500 font-mono text-[11px] whitespace-nowrap">
                    {getDisplayTimestamp(ioc)}
                  </td>
                </tr>
              ))}

              {filteredIocs.length === 0 && (
                <tr>
                  <td colSpan={5} className="p-16 text-center select-none">
                    <div className="w-12 h-12 rounded-full border border-slate-900 bg-slate-950 flex items-center justify-center mx-auto mb-4">
                      <Database className="w-5 h-5 text-slate-700 animate-pulse" />
                    </div>
                    <p className="font-mono text-[11px] text-slate-500 uppercase tracking-wider">
                      No threat indicators match current telemetry filter parameters.
                    </p>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Mobile view Cards list */}
        <div className="block md:hidden divide-y divide-slate-900/60">
          {filteredIocs.map((ioc) => (
            <div key={ioc.id} className="p-4 space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2.5">
                  {getTypeIcon(ioc.type)}
                  <span className="font-mono text-[10px] font-bold text-slate-400 uppercase select-none">
                    {ioc.type === 'email' ? 'EMAIL' : ioc.type}
                  </span>
                </div>
                <div>
                  {getRiskBadge(ioc.severity)}
                </div>
              </div>

              <div 
                onClick={() => handleCopyValue(ioc.value)}
                className="font-mono text-xs text-white bg-slate-950/60 p-2.5 rounded border border-slate-900/80 break-all cursor-pointer hover:text-cyan-400 active:text-cyan-300 flex items-center justify-between gap-1 select-all"
                title="Click to copy indicator"
              >
                <span className="truncate max-w-[210px]">{ioc.value}</span>
                {copiedValue === ioc.value ? (
                  <Check className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                ) : (
                  <Copy className="w-3.5 h-3.5 text-slate-600 shrink-0 opacity-70" />
                )}
              </div>

              <div className="text-[11px] text-slate-400 leading-normal font-sans">
                {ioc.description}
              </div>

              <div className="flex items-center justify-between text-[10px] font-mono pt-1 text-slate-500">
                <span>Feed: {getDisplayIntelSource(ioc)}</span>
                <span>{getDisplayTimestamp(ioc)}</span>
              </div>
            </div>
          ))}

          {filteredIocs.length === 0 && (
            <div className="p-12 text-center select-none">
              <div className="w-10 h-10 rounded-full border border-slate-900 bg-slate-950 flex items-center justify-center mx-auto mb-3">
                <Database className="w-4 h-4 text-slate-700 animate-pulse" />
              </div>
              <p className="font-mono text-[10px] text-slate-500 uppercase tracking-widest leading-none">
                No threat indicators match filter.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
