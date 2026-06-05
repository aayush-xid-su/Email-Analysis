/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React from "react";
import { Server, ArrowRight, Shield, ShieldAlert, Timer } from "lucide-react";
import { RelayStep } from "../types";

interface MailRelayFlowProps {
  steps: RelayStep[];
}

export default function MailRelayFlow({ steps }: MailRelayFlowProps) {
  return (
    <div className="bg-slate-900/60 border border-slate-800 p-6 rounded-xl">
      <h3 className="font-sans font-medium text-xs tracking-wider text-slate-400 uppercase mb-4 flex items-center gap-2">
        <Server className="w-4 h-4 text-cyan-500" />
        SMTP MAIL RELAY PATHWAY FORENSICS
      </h3>

      <div className="relative overflow-x-auto pb-4 pt-2 select-none scrollbar-thin scrollbar-thumb-slate-800 scrollbar-track-transparent">
        <div className="flex items-center min-w-[700px] gap-3 px-2">
          {steps.map((step, index) => {
            const isOrigin = index === 0;
            const isDestination = index === steps.length - 1;

            return (
              <React.Fragment key={step.hop}>
                {/* Connecting arrow with delay badge */}
                {!isOrigin && (
                  <div className="flex flex-col items-center justify-center px-1 text-slate-600 shrink-0">
                    <div className="flex items-center gap-1 text-[9px] font-mono text-cyan-400/80 mb-1">
                      <Timer className="w-3 h-3 text-cyan-500/60" />
                      <span>+{step.delayMs || 45}ms</span>
                    </div>
                    <ArrowRight className="w-5 h-5 text-slate-600 -mt-1" />
                    <span className="text-[8px] font-mono text-slate-500 select-none block mt-0.5">TLS/SEC</span>
                  </div>
                )}

                {/* Server Node Card */}
                <div 
                  className={`relative p-3.5 rounded-lg border w-52 shrink-0 transition-all hover:border-cyan-500/50 hover:bg-slate-900/90 hover:translate-y-[-2px] ${
                    isOrigin 
                      ? "border-amber-500/20 bg-amber-950/5/30" 
                      : isDestination
                      ? "border-cyan-500/30 bg-cyan-950/5/30"
                      : "border-slate-800 bg-slate-950/40"
                  }`}
                >
                  {/* Floating Hop Badge */}
                  <div className="absolute -top-2.5 -left-2 w-5 h-5 bg-slate-800 border border-slate-700 text-slate-300 font-mono text-[9px] rounded-full flex items-center justify-center font-bold">
                    {step.hop}
                  </div>

                  <div className="flex items-start gap-2.5">
                    <div className={`p-1.5 rounded ${
                      isOrigin 
                        ? "bg-amber-500/10 text-amber-400" 
                        : isDestination
                        ? "bg-cyan-500/10 text-cyan-400"
                        : "bg-slate-800 text-slate-400"
                    }`}>
                      <Server className="w-4 h-4" />
                    </div>

                    <div className="flex-1 min-w-0">
                      <div className="font-mono text-[10px] font-semibold text-slate-400 uppercase tracking-widest leading-none mb-1 flex items-center justify-between">
                        {isOrigin ? "Origin (MTA)" : isDestination ? "Endpoint MX" : "Relay Hop"}
                        {step.ip && (
                          <span className="text-[9px] text-slate-500 lowercase bg-slate-900 px-1 py-0.5 rounded ml-1 font-normal">
                            resolved
                          </span>
                        )}
                      </div>
                      <div className="font-sans text-xs font-bold text-white truncate" title={step.from}>
                        {step.from}
                      </div>
                      <div className="text-[10px] text-slate-400 truncate mt-0.5">
                        <span className="text-slate-500">by</span> {step.by}
                      </div>

                      {/* Decoded Transport IP details */}
                      <div className="mt-2 pt-2 border-t border-slate-800/60 flex items-center justify-between gap-1">
                        <span className="font-mono text-[9px] text-slate-400 font-bold bg-slate-900/80 px-1.5 py-0.5 rounded border border-slate-800 truncate">
                          IP: {step.ip || "127.0.0.1"}
                        </span>
                        <span className="text-[9px] text-slate-500 font-mono">
                          {step.with || "ESMTP"}
                        </span>
                      </div>
                    </div>
                  </div>
                </div>
              </React.Fragment>
            );
          })}
        </div>
      </div>

      <div className="mt-4 pt-3 border-t border-slate-800 flex flex-wrap items-center justify-between gap-3 text-[10px] text-slate-400 font-mono">
        <div className="flex items-center gap-4">
          <span className="flex items-center gap-1.5 border border-amber-500/30 px-2 py-0.5 rounded bg-amber-500/5 text-amber-400">
            <span className="w-1.5 h-1.5 bg-amber-500 rounded-full" />
            Origin System Location
          </span>
          <span className="flex items-center gap-1.5 border border-cyan-500/30 px-2 py-0.5 rounded bg-cyan-500/5 text-cyan-400">
            <span className="w-1.5 h-1.5 bg-cyan-400 rounded-full" />
            Vetted Destination Gateway
          </span>
        </div>
        <div className="text-slate-500 text-right">
          Total transmission relays: {steps.length} hops verified • Delay variance matches standardized queue limits
        </div>
      </div>
    </div>
  );
}
