import React, { useState, useEffect } from "react";
import { 
  Mail, 
  Lock, 
  Shield, 
  ShieldAlert, 
  Key, 
  RefreshCw, 
  ExternalLink, 
  Inbox, 
  CheckCircle, 
  AlertTriangle, 
  Cpu, 
  Wifi, 
  Loader2,
  BadgeAlert,
  ArrowRight
} from "lucide-react";

interface GmailMessage {
  id: string;
  from: string;
  subject: string;
  date: string;
  snippet: string;
  scanned: boolean;
}

interface GmailHubProps {
  onSelectReport: (reportId: string) => void;
  triggerToast: (msg: string) => void;
  syncPlatformData: () => Promise<void>;
}

export default function GmailHub({ onSelectReport, triggerToast, syncPlatformData }: GmailHubProps) {
  // Connection states
  const [loadingStatus, setLoadingStatus] = useState(true);
  const [connection, setConnection] = useState<{
    connected: boolean;
    isDemoMode: boolean;
    email: string;
    accessToken: string;
    autoScan: boolean;
  }>({
    connected: false,
    isDemoMode: false,
    email: "",
    accessToken: "",
    autoScan: false
  });

  const [customToken, setCustomToken] = useState("");
  const [customEmail, setCustomEmail] = useState("");
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [activeConfigTab, setActiveConfigTab] = useState<"auth" | "manual">("auth");
  const [oauthClientId, setOauthClientId] = useState(() => localStorage.getItem("mailrecon_gmail_client_id") || "");
  
  // Mailbox states
  const [messages, setMessages] = useState<GmailMessage[]>([]);
  const [fetchingMessages, setFetchingMessages] = useState(false);
  const [scanningMessageId, setScanningMessageId] = useState<string | null>(null);
  
  // Terminal logs for manual scanning
  const [logs, setLogs] = useState<string[]>([]);

  // Check URL Hash on load: Capture Google OAuth implicit grant token callback redirection
  useEffect(() => {
    if (window.location.hash) {
      const hashContent = window.location.hash.substring(1);
      const params = new URLSearchParams(hashContent);
      const token = params.get("access_token");
      const state = params.get("state");

      if (token && state === "mailrecon_oauth") {
        setLoadingStatus(true);
        // Clear hash so URL is pristine and shareable
        window.history.replaceState(null, "", window.location.pathname);
        
        // Fetch matching email from userinfo profile API to connect seamlessly
        fetch("https://www.googleapis.com/oauth2/v2/userinfo", {
          headers: { Authorization: `Bearer ${token}` }
        })
        .then(async (res) => {
          if (res.ok) {
            const userData = await res.json();
            const userEmail = userData.email;
            
            // Connect profile values onto API
            const connRes = await fetch("/api/gmail/connect", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({
                isDemoMode: false,
                email: userEmail,
                accessToken: token
              })
            });

            if (connRes.ok) {
              const data = await connRes.json();
              setConnection(data);
              localStorage.setItem("mailrecon_gmail_connection", JSON.stringify(data));
              triggerToast(`Authentication Completed: Connected directly to mailbox "${userEmail}"`);
              setLogs(prev => [
                `[${new Date().toLocaleTimeString()}] Live OAuth Callback intercepted successfully.`,
                `[${new Date().toLocaleTimeString()}] Handshake success: active session established for ${userEmail}.`,
                ...prev
              ]);
            } else {
              triggerToast("Gateway API rejected Google OAuth token context.");
            }
          } else {
            triggerToast("Failed to verify user profile from Google accounts database.");
          }
        })
        .catch(err => {
          console.error("Live Workspace Implicit flow error:", err);
          triggerToast("Implicit authorization flow handshake failed.");
        })
        .finally(() => {
          setLoadingStatus(false);
        });
      }
    }
  }, []);

  // Launch implicit grant Google accounts prompt
  const handleLaunchGoogleLogin = () => {
    if (!oauthClientId) {
      triggerToast("Please input your Web App Client ID from Google Cloud credentials manager.");
      return;
    }
    
    // Persist client ID so they do not type it again
    localStorage.setItem("mailrecon_gmail_client_id", oauthClientId);
    
    const rootUrl = "https://accounts.google.com/o/oauth2/v2/auth";
    const scopes = ["https://www.googleapis.com/auth/gmail.readonly"].join(" ");
    
    const params = new URLSearchParams({
      client_id: oauthClientId,
      redirect_uri: window.location.origin + window.location.pathname,
      response_type: "token",
      scope: scopes,
      state: "mailrecon_oauth",
      prompt: "select_account"
    });

    setLogs(prev => [
      `[${new Date().toLocaleTimeString()}] Triggering redirection port to Google Accounts platform...`,
      ...prev
    ]);

    // Redirection
    window.location.href = `${rootUrl}?${params.toString()}`;
  };

  // Fetch current status on mount
  const fetchStatus = async () => {
    try {
      const res = await fetch("/api/gmail/status");
      if (res.ok) {
        const data = await res.json();
        let finalData = data;

        if (!data.connected) {
          const savedStr = localStorage.getItem("mailrecon_gmail_connection");
          if (savedStr) {
            try {
              const saved = JSON.parse(savedStr);
              if (saved && saved.connected) {
                // Auto-repair the disconnect on server by re-connecting silently
                const restoreRes = await fetch("/api/gmail/connect", {
                  method: "POST",
                  headers: { "Content-Type": "application/json" },
                  body: JSON.stringify({
                    isDemoMode: saved.isDemoMode,
                    email: saved.email,
                    accessToken: saved.accessToken
                  })
                });
                if (restoreRes.ok) {
                  finalData = await restoreRes.json();
                }
              }
            } catch (localErr) {
              console.error("Local storage token recovery handshakes failed:", localErr);
            }
          }
        } else {
          // Keep local storage synchronized with server's valid state
          localStorage.setItem("mailrecon_gmail_connection", JSON.stringify(data));
        }

        setConnection(finalData);
        
        // Initialize terminal logs matching setup
        const initLogs = [
          `[${new Date().toLocaleTimeString()}] System: MailRecon Gmail Gateway online.`,
          `[${new Date().toLocaleTimeString()}] System: Channel interface initialized...`
        ];
        if (finalData.connected) {
          initLogs.push(`[${new Date().toLocaleTimeString()}] Authenticated: Active link synchronized for ${finalData.email}.`);
          initLogs.push(`[${new Date().toLocaleTimeString()}] System: Direct manual analysis core active.`);
        } else {
          initLogs.push(`[${new Date().toLocaleTimeString()}] Status: Disconnected. Awaiting authorization handshake.`);
        }
        setLogs(initLogs);
      }
    } catch (err) {
      console.error("Failed to fetch gmail connection status:", err);
    } finally {
      setLoadingStatus(false);
    }
  };

  useEffect(() => {
    fetchStatus();
  }, []);

  // Automated background polling has been completely removed to conserve server resources and Gmail API limit capacity.
  useEffect(() => {
    // Left empty deliberately. Direct manual audit triggers run on user request.
  }, [connection.connected]);

  // Fetch folder list
  const fetchMessages = async () => {
    if (!connection.connected) return;
    setFetchingMessages(true);
    try {
      const res = await fetch("/api/gmail/messages");
      if (res.ok) {
        const list = await res.json();
        setMessages(list);
      } else {
        triggerToast("Mailbox sync rejected by remote Google auth headers.");
      }
    } catch (err) {
      console.error("Error fetching messages:", err);
    } finally {
      setFetchingMessages(false);
    }
  };

  useEffect(() => {
    if (connection.connected) {
      fetchMessages();
    }
  }, [connection.connected]);

  // Handle Real OAuth connect
  const handleConnectReal = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!customToken || !customEmail) {
      triggerToast("Please provide both target Gmail address and valid Access Token.");
      return;
    }

    setLoadingStatus(true);
    try {
      const res = await fetch("/api/gmail/connect", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          isDemoMode: false,
          email: customEmail,
          accessToken: customToken
        })
      });

      if (res.ok) {
        const data = await res.json();
        setConnection(data);
        localStorage.setItem("mailrecon_gmail_connection", JSON.stringify(data));
        triggerToast(`Gateway Connected Live: Google Mail authorization synchronised for ${customEmail}`);
        setLogs(prev => [
          `[${new Date().toLocaleTimeString()}] Live Auth Handshake Complete: Connected.`,
          `[${new Date().toLocaleTimeString()}] Target Inbox: ${customEmail}`,
          ...prev
        ]);
      } else {
        triggerToast("Failed to link authorization profile. Credentials expired.");
      }
    } catch (err) {
      console.error("Real Gmail integration error:", err);
    } finally {
      setLoadingStatus(false);
    }
  };

  // Handle Disconnect Gateway
  const handleDisconnect = async () => {
    setLoadingStatus(true);
    try {
      const res = await fetch("/api/gmail/disconnect", { method: "POST" });
      if (res.ok) {
        const data = await res.json();
        setConnection(data);
        setMessages([]);
        localStorage.removeItem("mailrecon_gmail_connection");
        triggerToast("Workspace tunnel successfully severed. Offline storage preserved.");
        setLogs(prev => [
          `[${new Date().toLocaleTimeString()}] Secure Tunnel Disconnected.`,
          ...prev
        ]);
      }
    } catch (err) {
      console.error("Disconnect failure:", err);
    } finally {
      setLoadingStatus(false);
    }
  };

  // Trigger individual Past email scan & analyze
  const handleScanEmail = async (id: string, subject: string) => {
    setScanningMessageId(id);
    triggerToast(`Initializing full forensics scan for: "${subject}"`);
    setLogs(prev => [
      `[${new Date().toLocaleTimeString()}] Scan initiated for message node ${id}`,
      `[${new Date().toLocaleTimeString()}] Fetching raw body & headers envelope...`,
      ...prev
    ]);

    try {
      const res = await fetch("/api/gmail/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id })
      });

      if (res.ok) {
        const report = await res.json();
        triggerToast(`Intrusion scan COMPLETED: ${report.threatScore.level.toUpperCase()} risk index.`);
        setLogs(prev => [
          `[${new Date().toLocaleTimeString()}] ✅ Scan Success for MSG ${id}. Threat Score: ${report.threatScore.score}/100 (${report.threatScore.level.toUpperCase()})`,
          ...prev
        ]);
        
        // Refresh root reports list
        await syncPlatformData();
        // Refresh lists in current view
        fetchMessages();
        
        // Open the completed incident investigation report tab in front panel!
        setTimeout(() => {
          onSelectReport(report.id);
        }, 1000);
      } else {
        const errData = await res.json();
        triggerToast(`Verification Failed: ${errData.error || "MIME extraction error."}`);
      }
    } catch (err) {
      console.error("Scan error:", err);
      triggerToast("Forensics server rejected API requests.");
    } finally {
      setScanningMessageId(null);
    }
  };

  // Automated background controls are disabled. Direct manual audit provides full coverage.

  if (loadingStatus) {
    return (
      <div className="py-24 flex flex-col items-center justify-center text-center select-none">
        <Loader2 className="w-8 h-8 text-cyan-500 animate-spin mb-4" />
        <p className="font-mono text-xs text-slate-400">Negotiating MailRecon Gateway tunnels...</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 select-none pb-4 border-b border-slate-900">
        <div>
          <h1 className="font-sans font-extrabold text-xl tracking-tight text-white flex items-center gap-2.5">
            <Mail className="w-5 h-5 text-cyan-400" />
            Gmail Gateway Integration
          </h1>
          <p className="font-mono text-[11px] text-slate-500 mt-1 uppercase tracking-wider">
            Enterprise Mailbox Scanners & Real-Time Incoming Webhook Sentinels
          </p>
        </div>
      </div>      {/* Disconnected State: Setup UI */}
      {!connection.connected ? (
        <div className="grid md:grid-cols-5 gap-6">
          <div className="md:col-span-3 space-y-6">
            <div className="border border-slate-800 bg-slate-950/40 p-6 rounded-2xl relative overflow-hidden space-y-4">
              <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-cyan-500 to-indigo-500" />
              <div className="p-3 bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 rounded-xl w-fit">
                <Shield className="w-5 h-5 animate-pulse" />
              </div>
              <div className="space-y-1">
                <h3 className="font-sans font-bold text-sm text-white">Gmail Tunnel Offline</h3>
                <p className="text-xs text-slate-400 leading-relaxed font-sans mt-1">
                  Connect your corporate or personal email using one of our live integration gateways to audit incoming messages for cryptographic integrity, phishing, and cybersecurity threats in real-time.
                </p>
              </div>
            </div>

            <div className="border border-slate-850 bg-slate-950/70 p-5 rounded-2xl space-y-4">
              {/* Tabs */}
              <div className="flex border-b border-slate-900 pb-1 gap-4 select-none">
                <button
                  type="button"
                  onClick={() => setActiveConfigTab("auth")}
                  className={`font-sans font-bold text-xs uppercase tracking-wider pb-2 relative transition-all cursor-pointer ${
                    activeConfigTab === "auth" ? "text-cyan-400" : "text-slate-500 hover:text-slate-350"
                  }`}
                >
                  Google OAuth login
                  {activeConfigTab === "auth" && (
                    <div className="absolute bottom-0 left-0 w-full h-[1.5px] bg-cyan-400 rounded" />
                  )}
                </button>
                <button
                  type="button"
                  onClick={() => setActiveConfigTab("manual")}
                  className={`font-sans font-bold text-xs uppercase tracking-wider pb-2 relative transition-all cursor-pointer ${
                    activeConfigTab === "manual" ? "text-cyan-400" : "text-slate-500 hover:text-slate-350"
                  }`}
                >
                  Playground Token Helper
                  {activeConfigTab === "manual" && (
                    <div className="absolute bottom-0 left-0 w-full h-[1.5px] bg-cyan-400 rounded" />
                  )}
                </button>
              </div>

              {activeConfigTab === "auth" ? (
                <div className="space-y-4 animate-fadeIn">
                  <div className="space-y-1">
                    <h4 className="font-sans font-bold text-xs text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
                      <Shield className="w-3.5 h-3.5 text-cyan-400" />
                      Automated Client-side Redirection Port
                    </h4>
                    <p className="text-[11px] text-slate-500 leading-relaxed font-sans">
                      Authorizes standard OAuth2 implicit grant flow to download incoming emails without backend secrets. Input your custom Google Cloud Web Client ID below and trigger the official Google account picker.
                    </p>
                  </div>

                  <div className="space-y-1.5">
                    <label className="block text-[10px] font-bold font-mono text-slate-450 uppercase tracking-wider">
                      Google client ID (Web Application)
                    </label>
                    <input
                      type="text"
                      placeholder="e.g. 1048259102-xxxxxxxxxxxx.apps.googleusercontent.com"
                      value={oauthClientId}
                      onChange={(e) => setOauthClientId(e.target.value)}
                      className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2 font-mono text-[11px] text-slate-200 placeholder:text-slate-700 focus:outline-none focus:border-cyan-500 transition-all"
                    />
                  </div>

                  <div className="pt-2 flex justify-start">
                    <button
                      type="button"
                      onClick={handleLaunchGoogleLogin}
                      className="gsi-material-button px-5 py-2.5 rounded-xl text-xs font-semibold font-sans bg-indigo-600 hover:bg-indigo-500 text-white transition-all flex items-center gap-2.5 cursor-pointer shadow-lg shadow-indigo-600/10"
                    >
                      <svg className="w-4 h-4" viewBox="0 0 48 48">
                        <path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"></path>
                        <path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"></path>
                        <path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"></path>
                        <path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"></path>
                      </svg>
                      <span>Sign in with Google</span>
                    </button>
                  </div>
                </div>
              ) : (
                <form onSubmit={handleConnectReal} className="space-y-4 animate-fadeIn">
                  <div className="space-y-1">
                    <h4 className="font-sans font-bold text-xs text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
                      <Key className="w-3.5 h-3.5 text-cyan-400" />
                      Google Developer OAuth Playground Portal
                    </h4>
                    <p className="text-[11px] text-slate-500 leading-relaxed font-sans">
                      Don't have a configured Google Cloud client ID? Generate a live token in seconds:
                      <br />
                      1. Visit the <a href="https://developers.google.com/oauthplayground" target="_blank" rel="noopener noreferrer" className="text-cyan-400 hover:underline inline-flex items-center gap-0.5 font-bold">Google API Playground <ExternalLink className="w-2.5 h-2.5 inline" /></a>
                      <br />
                      2. Under Step 1, select <strong className="text-slate-300">Gmail API v1</strong> and authorize <code className="text-cyan-400 font-mono text-[10px]">https://www.googleapis.com/auth/gmail.readonly</code>.
                      <br />
                      3. Complete credentials checks, click "Exchange Auth Code", and paste the resulting trial token below.
                    </p>
                  </div>

                  <div className="grid sm:grid-cols-2 gap-4">
                    <div className="space-y-1.5">
                      <label className="block text-[10px] font-bold font-mono text-slate-400 uppercase tracking-wider">
                        Gmail Address
                      </label>
                      <input
                        type="email"
                        required
                        placeholder="e.g. security-analyst@gmail.com"
                        value={customEmail}
                        onChange={(e) => setCustomEmail(e.target.value)}
                        className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 font-mono text-xs text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500 transition-all"
                      />
                    </div>

                    <div className="space-y-1.5">
                      <label className="block text-[10px] font-bold font-mono text-slate-400 uppercase tracking-wider">
                        OAuth Access Token
                      </label>
                      <input
                        type="password"
                        required
                        placeholder="ya29.a0Acvnb..."
                        value={customToken}
                        onChange={(e) => setCustomToken(e.target.value)}
                        className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 font-mono text-xs text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500 transition-all"
                      />
                    </div>
                  </div>

                  <div className="pt-1 flex justify-end">
                    <button
                      type="submit"
                      className="px-4 py-2.5 rounded-xl text-xs font-semibold font-sans bg-indigo-600 hover:bg-indigo-550 text-white transition-all flex items-center gap-2 cursor-pointer shadow-lg shadow-indigo-600/10"
                    >
                      Authenticate Live Bearer Token
                      <ArrowRight className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </form>
              )}
            </div>
          </div>

          <div className="md:col-span-2 space-y-4">
            <div className="border border-slate-900 bg-slate-950/20 p-5 rounded-2xl space-y-3">
              <h3 className="font-sans font-bold text-xs text-slate-400 uppercase tracking-wider pb-2 border-b border-slate-900">
                Integration Specifications
              </h3>

              <div className="space-y-3 font-sans">
                <div className="flex gap-2.5 items-start">
                  <div className="p-1 rounded bg-slate-800/60 text-slate-400 mt-0.5 shrink-0">
                    <Shield className="w-3.5 h-3.5" />
                  </div>
                  <div>
                    <h4 className="text-xs font-bold text-slate-300">Read-Only Safety Standards</h4>
                    <p className="text-[11px] text-slate-500 leading-normal">
                      We negotiate read-only envelopes only. MailRecon has absolutely no permissions to delete, send, or edit your mailbox payloads.
                    </p>
                  </div>
                </div>

                <div className="flex gap-2.5 items-start">
                  <div className="p-1 rounded bg-slate-800/60 text-slate-400 mt-0.5 shrink-0">
                    <Cpu className="w-3.5 h-3.5" />
                  </div>
                  <div>
                    <h4 className="text-xs font-bold text-slate-300">Continuous Webhook Sentinel</h4>
                    <p className="text-[11px] text-slate-500 leading-normal">
                      Enabling the automation daemon initiates standard active polling representing continuous webhook execution to quarantine inbound threats immediately.
                    </p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      ) : (
        /* Connected State */
        <div className="space-y-6">
          {/* Channel Connection Banner */}
          <div className="border border-slate-850 bg-slate-950/40 p-5 rounded-2xl flex flex-col sm:flex-row sm:items-center justify-between gap-4 select-none relative overflow-hidden">
            <div className="absolute top-0 left-0 w-full h-0.5 bg-gradient-to-r from-emerald-500 via-teal-500 to-cyan-500" />
            <div className="flex items-start gap-3.5">
              <div className="p-3 rounded-xl border shrink-0 bg-emerald-500/10 border-emerald-500/25 text-emerald-400">
                <Inbox className="w-5 h-5 animate-pulse" />
              </div>
              <div className="space-y-0.5">
                <div className="flex items-center gap-2">
                  <span className="text-[9px] font-bold font-mono tracking-wider px-2 py-0.5 rounded-full bg-emerald-500/15 text-emerald-400 border border-emerald-500/20">
                    LIVE GOOGLE GMAIL API
                  </span>
                  <div className="w-2 h-2 rounded-full bg-emerald-500 animate-ping" />
                </div>
                <h3 className="font-sans font-extrabold text-sm text-white mt-1">
                  Connected: {connection.email}
                </h3>
                <p className="text-[10px] text-slate-500 font-mono tracking-normal">
                  Active Security Channel Sync • Integrity Status: Standard Compliance Secure
                </p>
              </div>
            </div>

            <button
              onClick={handleDisconnect}
              className="px-4 py-2 rounded-lg border border-slate-800 bg-slate-950/40 hover:bg-rose-950/10 hover:border-rose-500/20 text-slate-400 hover:text-rose-400 text-xs font-semibold font-sans transition-all cursor-pointer self-start sm:self-center"
            >
              Sever Gateway Connection
            </button>
          </div>

          <div className="grid xl:grid-cols-3 gap-6">
            {/* Past mailbox listing */}
            <div className="xl:col-span-2 space-y-4">
              <div className="border border-slate-850 bg-slate-950/40 p-5 rounded-2xl space-y-4">
                <div className="flex items-center justify-between pb-3 border-b border-slate-900">
                  <div className="flex items-center gap-2">
                    <Inbox className="w-4 h-4 text-slate-400" />
                    <h3 className="font-sans font-bold text-xs text-slate-300 uppercase tracking-wider">
                      Mailbox Folder: INBOX (Past Message Archive)
                    </h3>
                  </div>

                  <button
                    onClick={fetchMessages}
                    disabled={fetchingMessages}
                    className="p-1 px-2.5 rounded-lg border border-slate-800 bg-slate-950/40 text-slate-400 text-[10px] font-mono hover:text-white transition-all cursor-pointer flex items-center gap-1.5"
                  >
                    <RefreshCw className={`w-3 h-3 ${fetchingMessages ? "animate-spin" : ""}`} />
                    Sync Folder
                  </button>
                </div>

                {fetchingMessages && messages.length === 0 ? (
                  <div className="py-12 flex flex-col items-center justify-center text-center select-none">
                    <Loader2 className="w-6 h-6 text-indigo-400 animate-spin mb-3" />
                    <p className="font-mono text-xs text-slate-500">Querying mailbox directory envelope...</p>
                  </div>
                ) : messages.length === 0 ? (
                  <div className="py-12 text-center text-slate-500 font-sans text-xs select-none">
                    No records found in this folder list. Click Sync Folder above to inspect IMAP directory.
                  </div>
                ) : (
                  <>
                    <div className="hidden md:block overflow-x-auto">
                      <table className="w-full text-left border-collapse font-sans text-xs">
                        <thead>
                          <tr className="border-b border-slate-900 text-slate-500 select-none font-semibold text-[10px] uppercase tracking-wider">
                            <th className="pb-3 pt-1">Sender Info</th>
                            <th className="pb-3 pt-1">Subject & Preview</th>
                            <th className="pb-3 pt-1">Received Date</th>
                            <th className="pb-3 pt-1 text-right">MIME Actions</th>
                          </tr>
                        </thead>
                        <tbody>
                          {messages.map((msg) => (
                            <tr key={msg.id} className="border-b border-slate-900/40 hover:bg-slate-900/10 transition-colors">
                              <td className="py-3.5 pr-2 max-w-[140px] truncate">
                                <span className="font-medium text-slate-200 block truncate" title={msg.from}>
                                  {msg.from.replace(/"/g, "")}
                                </span>
                              </td>
                              <td className="py-3.5 px-2 max-w-[210px]">
                                <span className="font-semibold text-white block truncate">
                                  {msg.subject}
                                </span>
                                <span className="text-[11px] text-slate-500 block truncate mt-0.5 font-mono">
                                  {msg.snippet}
                                </span>
                              </td>
                              <td className="py-3.5 px-2 font-mono text-[10px] text-slate-400 whitespace-nowrap">
                                {msg.date.replace("GMT", "").replace(" +0000", "")}
                              </td>
                              <td className="py-3.5 pl-2 text-right whitespace-nowrap">
                                {msg.scanned ? (
                                  <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-teal-500/10 text-teal-400 font-mono text-[10px] font-bold border border-teal-500/20">
                                    <CheckCircle className="w-3 h-3 text-teal-400" />
                                    SCANNED & AUDITED
                                  </span>
                                ) : (
                                  <button
                                    onClick={() => handleScanEmail(msg.id, msg.subject)}
                                    disabled={scanningMessageId !== null}
                                    className="px-2.5 py-1.5 rounded-lg text-[10px] font-mono font-bold bg-cyan-500 hover:bg-cyan-400 text-slate-950 transition-all flex items-center justify-center gap-1.5 cursor-pointer ml-auto"
                                  >
                                    {scanningMessageId === msg.id ? (
                                      <>
                                        <Loader2 className="w-3 h-3 animate-spin" />
                                        AUDITING...
                                      </>
                                    ) : (
                                      <>
                                        <Shield className="w-3 h-3" />
                                        AUDIT EMAIL
                                      </>
                                    )}
                                  </button>
                                )}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>

                    {/* Mobile View Cards List */}
                    <div className="block md:hidden divide-y divide-slate-900/50">
                      {messages.map((msg) => (
                        <div key={msg.id} className="py-4 space-y-3">
                          <div className="flex items-center justify-between gap-2 text-[10px] font-mono">
                            <span className="text-slate-400 truncate max-w-[170px]" title={msg.from}>
                              {msg.from.replace(/"/g, "")}
                            </span>
                            <span className="text-slate-500 shrink-0">
                              {msg.date.replace("GMT", "").replace(" +0000", "")}
                            </span>
                          </div>

                          <div>
                            <span className="font-semibold text-white block text-xs leading-snug">
                              {msg.subject}
                            </span>
                            <span className="text-[11px] text-slate-500 block truncate mt-1 font-mono">
                              {msg.snippet}
                            </span>
                          </div>

                          <div className="flex justify-end pt-2 border-t border-slate-900/30">
                            {msg.scanned ? (
                              <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-teal-500/10 text-teal-400 font-mono text-[10px] font-bold border border-teal-500/20">
                                <CheckCircle className="w-3 h-3 text-teal-400" />
                                SCANNED & AUDITED
                              </span>
                            ) : (
                              <button
                                onClick={() => handleScanEmail(msg.id, msg.subject)}
                                disabled={scanningMessageId !== null}
                                className="px-3 py-1.5 rounded-xl text-[10px] font-mono font-bold bg-cyan-500 hover:bg-cyan-400 text-slate-950 transition-all flex items-center justify-center gap-1.5 cursor-pointer"
                              >
                                {scanningMessageId === msg.id ? (
                                  <>
                                    <Loader2 className="w-3 h-3 animate-spin" />
                                    AUDITING...
                                  </>
                                ) : (
                                  <>
                                    <Shield className="w-3 h-3" />
                                    AUDIT EMAIL
                                  </>
                                )}
                              </button>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  </>
                )}
              </div>
            </div>

            {/* Console Logs Side Column */}
            <div className="xl:col-span-1 space-y-4">
              <div className="border border-slate-850 bg-slate-950/40 p-5 rounded-1.5xl h-full flex flex-col min-h-[350px]">
                <div className="flex items-center justify-between border-b border-slate-900 pb-3 mb-4 select-none">
                  <div className="flex items-center gap-2">
                    <Cpu className="w-4 h-4 text-cyan-400" />
                    <span className="font-sans font-bold text-xs text-slate-300 uppercase tracking-wider">
                      Interactive Audit Live Output
                    </span>
                  </div>
                  <div className="flex gap-1.5">
                    <div className="w-1.5 h-1.5 rounded-full bg-slate-850" />
                    <div className="w-1.5 h-1.5 rounded-full bg-slate-850" />
                    <div className="w-1.5 h-1.5 rounded-full bg-slate-850" />
                  </div>
                </div>

                <div className="font-mono text-[10px] leading-relaxed text-cyan-500 overflow-y-auto max-h-[420px] flex-1 space-y-2">
                  {logs.length === 0 ? (
                    <div className="text-slate-500 italic">No direct logs recorded. Click Audit Email from the directory.</div>
                  ) : (
                    logs.map((log, i) => (
                      <div key={i} className="border-l border-slate-850 pl-2">
                        {log}
                      </div>
                    ))
                  )}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
