/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from "react";
import { Shield, ShieldCheck, Key, RefreshCw, Sparkles, Sliders, CheckCircle } from "lucide-react";

export default function SettingsView() {
  const [successMsg, setSuccessMsg] = useState("");
  const [mfaEnabled, setMfaEnabled] = useState(true);
  const [quarantineThreshold, setQuarantineThreshold] = useState("55");
  const [retentionPeriod, setRetentionPeriod] = useState("90");

  const handleSaveSettings = (e: React.FormEvent) => {
    e.preventDefault();
    setSuccessMsg("System configuration updated successfully. Routing tables sync completed.");
    setTimeout(() => setSuccessMsg(""), 3000);
  };

  return (
    <div className="max-w-3xl mx-auto space-y-6">
      {/* Settings Title */}
      <div className="p-6 bg-slate-900/40 border border-slate-800 rounded-xl">
        <h2 className="font-sans font-bold text-base text-white flex items-center gap-2">
          <Sliders className="w-5 h-5 text-cyan-500" />
          MailRecon Platform Configurations
        </h2>
        <p className="text-xs text-slate-400 mt-1">
          Administer SOC threat engine multipliers, backend cache variables, and integrations hooks.
        </p>
      </div>

      {successMsg && (
        <div className="p-3 bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs rounded-lg flex items-center gap-2 font-sans font-medium">
          <CheckCircle className="w-4 h-4 shrink-0" />
          <span>{successMsg}</span>
        </div>
      )}

      {/* Main Settings Form */}
      <form onSubmit={handleSaveSettings} className="space-y-6">
        
        {/* Gemini API Diagnostic Status */}
        <div className="bg-slate-900/40 border border-slate-800 p-5 rounded-xl space-y-3.5">
          <h3 className="font-sans font-semibold text-xs tracking-wider text-slate-400 uppercase flex items-center gap-1.5 border-b border-slate-800/80 pb-2">
            <Key className="w-4 h-4 text-cyan-405" />
            AI Cognitive Integrations Diagnostic
          </h3>

          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 p-3 bg-slate-950/60 rounded-lg border border-slate-850">
            <div>
              <div className="text-xs font-bold text-white flex items-center gap-1.5">
                <Sparkles className="w-3.5 h-3.5 text-cyan-400 animate-pulse" />
                Gemini-3.5-Flash Core Model
              </div>
              <p className="text-[10px] text-slate-400 mt-0.5 leading-snug">
                Used to compile deep analytical cyber forensics, recommendations, and malicious intent summaries.
              </p>
            </div>
            
            {/* Status light */}
            <div className="flex items-center gap-2 self-end sm:self-auto select-none">
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-cyan-500"></span>
              </span>
              <span className="font-mono text-[10px] font-bold text-cyan-300 uppercase">ACTIVE CONFIG</span>
            </div>
          </div>

          <p className="text-[10px] text-slate-500 font-mono leading-relaxed mt-1">
            * Note: API keys are integrated automatically through the AI Studio environment settings variables (GEMINI_API_KEY). Never commit static keys keys inside repository commits or code blocks.
          </p>
        </div>

        {/* SOC Policy Multiplexers */}
        <div className="bg-slate-900/40 border border-slate-800 p-5 rounded-xl space-y-4">
          <h3 className="font-sans font-semibold text-xs tracking-wider text-slate-400 uppercase flex items-center gap-1.5 border-b border-slate-800/80 pb-2">
            <Shield className="w-4 h-4 text-cyan-405" />
            Active Warning Quarantines Policies
          </h3>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            
            {/* Quarantine index */}
            <div>
              <label className="block text-[10px] font-mono text-slate-500 uppercase tracking-wider mb-1.5">
                Calculated Quarantine Threshold
              </label>
              <select
                value={quarantineThreshold}
                onChange={(e) => setQuarantineThreshold(e.target.value)}
                className="w-full px-3 py-2 rounded-lg border border-slate-800 bg-slate-950 font-sans text-xs text-slate-300 cursor-pointer outline-none focus:border-cyan-500/45"
              >
                <option value="40">Mild Threat (Score: 40+)</option>
                <option value="55">Moderate Audit Flag (Score: 55+)</option>
                <option value="75">Strict Block Limits (Score: 75+)</option>
                <option value="90">Extreme Attack Mitigation (Score: 90+)</option>
              </select>
              <p className="text-[9px] text-slate-500 mt-1">
                Emails calculating threat numbers exceeding threshold route directly to SOC inspection quarantines.
              </p>
            </div>

            {/* Retention */}
            <div>
              <label className="block text-[10px] font-mono text-slate-500 uppercase tracking-wider mb-1.5">
                Forensics History Retention Cache
              </label>
              <select
                value={retentionPeriod}
                onChange={(e) => setRetentionPeriod(e.target.value)}
                className="w-full px-3 py-2 rounded-lg border border-slate-800 bg-slate-950 font-sans text-xs text-slate-300 cursor-pointer outline-none focus:border-cyan-500/45"
              >
                <option value="30">30 Days audit log lifespan</option>
                <option value="90">90 Days standard investigation lifespan</option>
                <option value="365">1 Year compliance cache log</option>
              </select>
              <p className="text-[9px] text-slate-500 mt-1">
                Investigated metadata timelines automatically rotate or scrub files strictly matching periods.
              </p>
            </div>
          </div>

          {/* Secure toggles */}
          <div className="pt-2 border-t border-slate-850/60 flex items-center justify-between select-none">
            <div>
              <div className="text-xs font-bold text-white">Require Multi-Factor SOC Token Alignment</div>
              <p className="text-[10px] text-slate-550 leading-relaxed max-w-sm">
                Enforces cryptographically signed analyst keys during login sequences on endpoints.
              </p>
            </div>
            
            <button
              type="button"
              onClick={() => setMfaEnabled(!mfaEnabled)}
              className={`w-11 h-6 rounded-full p-1 transition-colors duration-300 outline-none shrink-0 cursor-pointer ${
                mfaEnabled ? "bg-cyan-500" : "bg-slate-800 border border-slate-700"
              }`}
            >
              <div className={`w-4 h-4 bg-white rounded-full transition-transform duration-300 transform ${
                mfaEnabled ? "translate-x-5" : "translate-x-0"
              }`} />
            </button>
          </div>
        </div>

        {/* Submit */}
        <button
          type="submit"
          className="px-6 py-2.5 bg-cyan-600 hover:bg-cyan-500 active:scale-95 duration-200 text-white font-sans font-bold text-xs rounded-lg cursor-pointer transition-all flex items-center justify-center gap-1.5 ml-auto"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          Update System Policies
        </button>
      </form>
    </div>
  );
}
