/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect } from "react";
import { 
  ShieldAlert, 
  LayoutDashboard, 
  Terminal, 
  Database, 
  Sliders, 
  RefreshCw, 
  CheckCircle,
  Clock,
  User as UserIcon,
  Shield,
  Activity,
  ChevronRight,
  Mail
} from "lucide-react";
import { EmailAnalysis, SocStats, User } from "./types";
import DashboardView from "./components/DashboardView";
import AnalyzeWorkspace from "./components/AnalyzeWorkspace";
import IocExplorer from "./components/IocExplorer";
import SettingsView from "./components/SettingsView";
import ReportView from "./components/ReportView";
import GmailHub from "./components/GmailHub";

export default function App() {
  // Auth state - Auto-login aligned directly
  const [token, setToken] = useState<string>(
    "jwt_sandbox_token_auto_aligned"
  );
  const [user, setUser] = useState<User>({
    id: "usr_1",
    email: "soc.analyst@mailrecon.internal",
    name: "SOC Analyst",
    role: "Tier-2 Security Analyst"
  });

  // Layout View Tabs: "dashboard" | "analyze" | "iocs" | "settings" | "report"
  const [activeTab, setActiveTab] = useState<string>("dashboard");
  const [selectedReportId, setSelectedReportId] = useState<string | null>(null);
  
  // Data lists
  const [emailsList, setEmailsList] = useState<any[]>([]);
  const [stats, setStats] = useState<SocStats | null>(null);
  const [selectedReport, setSelectedReport] = useState<EmailAnalysis | null>(null);
  const [loadingReport, setLoadingReport] = useState(false);
  const [allIocs, setAllIocs] = useState<any[]>([]);
  
  // Notification toasts
  const [toastMessage, setToastMessage] = useState("");

  const triggerToast = (msg: string) => {
    setToastMessage(msg);
    setTimeout(() => setToastMessage(""), 4000);
  };

  // Synchronizers: Fetch all telemetry
  const syncPlatformData = async () => {
    try {
      // 1. Fetch Stats
      const statsRes = await fetch("/api/stats");
      if (statsRes.ok) {
        const statsData = await statsRes.json();
        setStats(statsData);
      }

      // 2. Fetch Emails List
      const listRes = await fetch("/api/emails");
      if (listRes.ok) {
        const listData = await listRes.json();
        setEmailsList(listData);
      }

      // 3. Fetch Aggregated IOCs
      const iocRes = await fetch("/api/iocs");
      if (iocRes.ok) {
        const iocData = await iocRes.json();
        setAllIocs(iocData);
      }
    } catch (err) {
      console.error("Unable to sync MailRecon data from server endpoints:", err);
    }
  };

  useEffect(() => {
    if (token) {
      syncPlatformData();
    }
  }, [token]);

  // Auth logins handler
  const handleLoginSuccess = (userToken: string, userProfile: User) => {
    localStorage.setItem("mailrecon_token", userToken);
    localStorage.setItem("mailrecon_user", JSON.stringify(userProfile));
    setToken(userToken);
    setUser(userProfile);
    triggerToast("Access authentication successful. Portal tunnel synchronized.");
  };

  const handleRefresh = async () => {
    await syncPlatformData();
    triggerToast("SOC platform feed synced with latest active telemetry.");
  };

  // Analyze: Paste raw or file upload
  const handleAnalyzeFile = async (fileName: string, fileContent: string) => {
    const res = await fetch("/api/analyze/upload", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ fileName, fileContent })
    });

    if (!res.ok) {
      throw new Error("SMTP structure parser rejected the file parameters.");
    }

    const reportData = await res.json();
    setSelectedReport(reportData);
    setSelectedReportId(reportData.id);
    setActiveTab("report");
    await syncPlatformData();
    triggerToast(`Analysis completed for: ${fileName}`);
    return reportData;
  };

  const handleAnalyzePaste = async (subject: string, rawContent: string) => {
    const res = await fetch("/api/analyze/pasted", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ subject, rawContent })
    });

    if (!res.ok) {
      throw new Error("Parser rejected the pasted SMTP header details.");
    }

    const reportData = await res.json();
    setSelectedReport(reportData);
    setSelectedReportId(reportData.id);
    setActiveTab("report");
    await syncPlatformData();
    triggerToast("Paste buffer analyzed successfully.");
    return reportData;
  };

  // Inspect specific case ID
  const handleInvestigateReport = async (id: string) => {
    setLoadingReport(true);
    try {
      const res = await fetch(`/api/emails/${id}`);
      if (res.ok) {
        const data = await res.json();
        setSelectedReport(data);
        setSelectedReportId(id);
        setActiveTab("report");
      } else {
        triggerToast("Report was unavailable or deleted from active index.");
      }
    } catch (err) {
      triggerToast("Failed fetching case file.");
    }
    setLoadingReport(false);
  };

  // Delete/Archive case file
  const handleDeleteReport = async (id: string) => {
    try {
      const res = await fetch(`/api/emails/${id}`, { method: "DELETE" });
      if (res.ok) {
        triggerToast("Investigation archived successfully.");
        setActiveTab("dashboard");
        setSelectedReport(null);
        setSelectedReportId(null);
        await syncPlatformData();
      }
    } catch (err) {
      triggerToast("Archival sequence failed.");
    }
  };

  // Direct tab triggers
  const navigateToTab = (tabName: string) => {
    setActiveTab(tabName);
    setSelectedReport(null);
    setSelectedReportId(null);
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans select-none antialiased">
      
      {/* Visual background atmospheric elements */}
      <div className="fixed top-0 left-0 w-full h-full bg-[radial-gradient(#1e293b_1px,transparent_1px)] [background-size:24px_24px] opacity-15 pointer-events-none" />

      {/* Top Main SOC Ribbon Bar */}
      <header className="border-b border-slate-800 bg-slate-900/60 sticky top-0 z-40 backdrop-blur-md px-6 py-4 flex items-center justify-between pointer-events-auto print:hidden">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 shadow-lg shadow-cyan-950/20">
            <ShieldAlert className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="font-sans font-black text-sm text-white tracking-widest uppercase text-glow-cyan">
                MailRecon
              </h1>
              <span className="px-1.5 py-0.5 rounded text-[8px] font-mono border border-cyan-500/35 bg-cyan-950/15 text-cyan-400 font-bold tracking-widest leading-none">
                SOC-HQ
              </span>
            </div>
            <p className="text-[10px] text-slate-500 font-mono mt-0.5 uppercase tracking-wider">
              AI-Powered Email Threat Intelligence Console
            </p>
          </div>
        </div>

        {/* Sync Button */}
        <div className="flex items-center">
          <button
            onClick={handleRefresh}
            className="p-2 rounded-lg border border-slate-800 bg-slate-950/40 hover:bg-cyan-950/10 text-slate-400 hover:text-cyan-400 transition-all cursor-pointer flex items-center justify-center"
            title="Sync Platform Feeds"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </header>

      {/* Main Structural Framework Layout */}
      <div className="flex-1 flex max-w-7xl w-full mx-auto px-6 py-8 gap-8 relative z-10">
        
        {/* Left Navigation Sidebar Desktop */}
        <aside className="w-64 shrink-0 flex flex-col gap-6 select-none print:hidden hidden md:block">
          
          <nav className="space-y-1.5">
            {/* Dashboard */}
            <button
              onClick={() => navigateToTab("dashboard")}
              className={`w-full p-3 rounded-xl border font-sans font-semibold text-xs transition-all cursor-pointer flex items-center justify-between text-left ${
                activeTab === "dashboard"
                  ? "border-cyan-500/30 bg-cyan-950/10 text-cyan-400"
                  : "border-transparent text-slate-400 hover:text-slate-300 hover:bg-slate-900/40"
              }`}
            >
              <span className="flex items-center gap-3">
                <LayoutDashboard className="w-4 h-4 shrink-0" />
                <span>Ground Dashboard</span>
              </span>
              <ChevronRight className={`w-3.5 h-3.5 opacity-60 ${activeTab === "dashboard" ? "block" : "hidden"}`} />
            </button>

            {/* Analyze workspace */}
            <button
              onClick={() => navigateToTab("analyze")}
              className={`w-full p-3 rounded-xl border font-sans font-semibold text-xs transition-all cursor-pointer flex items-center justify-between text-left ${
                activeTab === "analyze"
                  ? "border-cyan-500/30 bg-cyan-950/10 text-cyan-400"
                  : "border-transparent text-slate-400 hover:text-slate-300 hover:bg-slate-900/40"
              }`}
            >
              <span className="flex items-center gap-3">
                <Terminal className="w-4 h-4 shrink-0" />
                <span>Forensics Scanner</span>
              </span>
              <ChevronRight className={`w-3.5 h-3.5 opacity-60 ${activeTab === "analyze" ? "block" : "hidden"}`} />
            </button>

            {/* Gmail Gateway */}
            <button
              onClick={() => navigateToTab("gmail")}
              className={`w-full p-3 rounded-xl border font-sans font-semibold text-xs transition-all cursor-pointer flex items-center justify-between text-left ${
                activeTab === "gmail"
                  ? "border-cyan-500/30 bg-cyan-950/10 text-cyan-400"
                  : "border-transparent text-slate-400 hover:text-slate-300 hover:bg-slate-900/40"
              }`}
            >
              <span className="flex items-center gap-3">
                <Mail className="w-4 h-4 shrink-0" />
                <span>Gmail Gateway</span>
              </span>
              <ChevronRight className={`w-3.5 h-3.5 opacity-60 ${activeTab === "gmail" ? "block" : "hidden"}`} />
            </button>

            {/* IOC database explorer */}
            <button
              onClick={() => navigateToTab("iocs")}
              className={`w-full p-3 rounded-xl border font-sans font-semibold text-xs transition-all cursor-pointer flex items-center justify-between text-left ${
                activeTab === "iocs"
                  ? "border-cyan-500/30 bg-cyan-950/10 text-cyan-400"
                  : "border-transparent text-slate-400 hover:text-slate-300 hover:bg-slate-900/40"
              }`}
            >
              <span className="flex items-center gap-3">
                <Database className="w-4 h-4 shrink-0" />
                <span>IOC Registry</span>
              </span>
              <ChevronRight className={`w-3.5 h-3.5 opacity-60 ${activeTab === "iocs" ? "block" : "hidden"}`} />
            </button>

            {/* Settings */}
            <button
              onClick={() => navigateToTab("settings")}
              className={`w-full p-3 rounded-xl border font-sans font-semibold text-xs transition-all cursor-pointer flex items-center justify-between text-left ${
                activeTab === "settings"
                  ? "border-cyan-500/30 bg-cyan-950/10 text-cyan-400"
                  : "border-transparent text-slate-400 hover:text-slate-300 hover:bg-slate-900/40"
              }`}
            >
              <span className="flex items-center gap-3">
                <Sliders className="w-4 h-4 shrink-0" />
                <span>Platform Policies</span>
              </span>
              <ChevronRight className={`w-3.5 h-3.5 opacity-60 ${activeTab === "settings" ? "block" : "hidden"}`} />
            </button>
          </nav>
        </aside>

        {/* Main Workspace Frame container */}
        <main className="flex-1 min-w-0">
          
          {/* Mobile Navigation controls */}
          <div className="flex md:hidden border-b border-slate-800 pb-2.5 mb-6 gap-2 overflow-x-auto overflow-y-hidden flex-nowrap text-xs select-none scrollbar-none snap-x print:hidden">
            <button
              onClick={() => navigateToTab("dashboard")}
              className={`px-3 py-1.5 rounded-lg border font-mono shrink-0 snap-center ${
                activeTab === "dashboard" ? "border-cyan-500 text-cyan-400 bg-cyan-950/10" : "border-slate-800 text-slate-400"
              }`}
            >
              Dashboard
            </button>
            <button
              onClick={() => navigateToTab("analyze")}
              className={`px-3 py-1.5 rounded-lg border font-mono shrink-0 snap-center ${
                activeTab === "analyze" ? "border-cyan-500 text-cyan-400 bg-cyan-950/10" : "border-slate-800 text-slate-400"
              }`}
            >
              Forensics
            </button>
            <button
              onClick={() => navigateToTab("gmail")}
              className={`px-3 py-1.5 rounded-lg border font-mono shrink-0 snap-center ${
                activeTab === "gmail" ? "border-cyan-500 text-cyan-400 bg-cyan-950/10" : "border-slate-800 text-slate-400"
              }`}
            >
              Gmail Gateway
            </button>
            <button
              onClick={() => navigateToTab("iocs")}
              className={`px-3 py-1.5 rounded-lg border font-mono shrink-0 snap-center ${
                activeTab === "iocs" ? "border-cyan-500 text-cyan-400 bg-cyan-950/10" : "border-slate-800 text-slate-400"
              }`}
            >
              IOC
            </button>
            <button
              onClick={() => navigateToTab("settings")}
              className={`px-3 py-1.5 rounded-lg border font-mono shrink-0 snap-center ${
                activeTab === "settings" ? "border-cyan-500 text-cyan-400 bg-cyan-950/10" : "border-slate-800 text-slate-400"
              }`}
            >
              Policies
            </button>
          </div>

          {/* Dynamic Tab view switcher content */}
          {loadingReport ? (
            <div className="py-24 flex flex-col items-center justify-center text-center select-none">
              <div className="w-10 h-10 rounded-full border-2 border-cyan-500/10 border-t-cyan-500 animate-spin mb-4" />
              <p className="font-mono text-xs text-slate-400">Opening investigation incident file...</p>
            </div>
          ) : activeTab === "dashboard" && stats ? (
            <DashboardView
              stats={stats}
              emailsList={emailsList}
              onSelectEmail={handleInvestigateReport}
              onNavigateToUpload={() => navigateToTab("analyze")}
              onRefresh={syncPlatformData}
            />
          ) : activeTab === "analyze" ? (
            <AnalyzeWorkspace
              onAnalyzeUploaded={handleAnalyzeFile}
              onAnalyzePasted={handleAnalyzePaste}
            />
          ) : activeTab === "gmail" ? (
            <GmailHub
              onSelectReport={handleInvestigateReport}
              triggerToast={triggerToast}
              syncPlatformData={syncPlatformData}
            />
          ) : activeTab === "iocs" ? (
            <IocExplorer iocs={allIocs} />
          ) : activeTab === "settings" ? (
            <SettingsView />
          ) : activeTab === "report" && selectedReport ? (
            <ReportView
              report={selectedReport}
              onBack={() => navigateToTab("dashboard")}
              onDeleteReport={handleDeleteReport}
            />
          ) : (
            <div className="py-24 text-center text-slate-500 font-mono text-xs select-none">
              Initializing neural threat engine database logs...
            </div>
          )}
        </main>
      </div>

      {/* Dynamic Toast Notifications */}
      {toastMessage && (
        <div className="fixed bottom-6 right-6 p-4 rounded-xl shadow-2xl border bg-slate-900 border-cyan-500/20 text-white flex items-center gap-3 text-xs select-none max-w-sm pointer-events-auto z-50 animate-bounce">
          <div className="p-2 bg-cyan-500/10 rounded text-cyan-400">
            <CheckCircle className="w-4 h-4" />
          </div>
          <div className="flex-1 min-w-0 pr-1">
            <div className="font-bold font-sans">SOC Platform Notification</div>
            <p className="text-slate-400 font-mono mt-0.5 leading-snug">{toastMessage}</p>
          </div>
        </div>
      )}

      {/* Sticky footer telemetry status */}
      <footer className="border-t border-slate-900 bg-slate-950/40 p-3 text-center text-[9px] font-mono text-slate-500 tracking-wider flex items-center justify-center gap-2 select-none shrink-0 print:hidden">
        <Activity className="w-3.5 h-3.5 text-cyan-500 animate-pulse" />
        <span>MAILRECON ENGINE v2.4.0 • SYSTEM LOGS INTEGRITY ENFORCED • INCIDENT CHRONOLOGY VERIFIED</span>
      </footer>
    </div>
  );
}
