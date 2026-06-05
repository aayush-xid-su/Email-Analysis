/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React from "react";
import { ShieldAlert, ShieldCheck, ShieldAlert as WarningIcon, Activity } from "lucide-react";
import { ThreatScore } from "../types";

interface ThreatMeterProps {
  score: ThreatScore;
}

export default function ThreatMeter({ score }: ThreatMeterProps) {
  const { score: val, level, confidence, factors } = score;

  // Calculate arc params for dynamic SVG gauge
  const radius = 50;
  const strokeWidth = 10;
  const normalizedRadius = radius - strokeWidth / 2;
  const circumference = normalizedRadius * 2 * Math.PI;
  const strokeDashoffset = circumference - (val / 100) * circumference;

  // Determine design color configurations based on hazard ratings
  const getSeverityStyles = () => {
    switch (level) {
      case "critical":
        return {
          text: "text-red-500",
          border: "border-red-500/30",
          bg: "bg-red-950/20",
          glow: "shadow-red-500/20",
          indicatorColor: "stroke-red-500",
          badge: "bg-red-500/10 text-red-400 border-red-500/30"
        };
      case "high":
        return {
          text: "text-amber-500",
          border: "border-amber-500/30",
          bg: "bg-amber-950/20",
          glow: "shadow-amber-500/20",
          indicatorColor: "stroke-amber-500",
          badge: "bg-amber-500/10 text-amber-400 border-amber-500/30"
        };
      case "medium":
        return {
          text: "text-yellow-400",
          border: "border-yellow-500/20",
          bg: "bg-yellow-950/10",
          glow: "shadow-yellow-500/10",
          indicatorColor: "stroke-yellow-400",
          badge: "bg-yellow-400/10 text-yellow-300 border-yellow-400/20"
        };
      default:
        return {
          text: "text-cyan-400",
          border: "border-cyan-500/20",
          bg: "bg-cyan-950/10",
          glow: "shadow-cyan-500/10",
          indicatorColor: "stroke-cyan-400",
          badge: "bg-cyan-500/10 text-cyan-400 border-cyan-500/20"
        };
    }
  };

  const colors = getSeverityStyles();

  return (
    <div className={`border p-6 rounded-xl ${colors.bg} ${colors.border} transition-all duration-300`}>
      <h3 className="font-sans font-medium text-xs tracking-wider text-slate-400 uppercase mb-4 flex items-center justify-between">
        Threat Scoring Evaluation
        <span className={`px-2 py-0.5 rounded text-[10px] font-mono border ${colors.badge}`}>
          {level.toUpperCase()}
        </span>
      </h3>

      <div className="flex flex-col md:flex-row items-center justify-around gap-6 py-2">
        {/* Animated Gauge Arc */}
        <div className="relative flex items-center justify-center w-36 h-36">
          <svg className="w-full h-full transform -rotate-90" viewBox="0 0 100 100">
            {/* Background Circle track */}
            <circle
              className="text-slate-800"
              strokeWidth={strokeWidth}
              stroke="currentColor"
              fill="transparent"
              r={normalizedRadius}
              cx="50"
              cy="50"
            />
            {/* Dynamic Threat indicator arc */}
            <circle
              className={`${colors.indicatorColor} transition-all duration-1000 ease-out`}
              strokeWidth={strokeWidth}
              strokeDasharray={circumference + " " + circumference}
              style={{ strokeDashoffset }}
              strokeLinecap="round"
              fill="transparent"
              r={normalizedRadius}
              cx="50"
              cy="50"
            />
          </svg>
          <div className="absolute text-center flex flex-col items-center">
            <span className="font-mono text-3xl font-bold tracking-tight text-white">{val}</span>
            <span className="font-mono text-[9px] text-slate-400 tracking-widest uppercase">Risk Score</span>
          </div>
        </div>

        {/* Core statistical outputs */}
        <div className="flex flex-col gap-3 max-w-xs w-full">
          <div className="bg-slate-900/40 p-3 rounded-lg border border-slate-800/60">
            <div className="text-[10px] font-mono tracking-wider text-slate-400 uppercase mb-1">Confidence Rating</div>
            <div className="flex items-center gap-2">
              <div className="flex-1 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                <div 
                  className="h-full bg-cyan-500 rounded-full transition-all duration-1000"
                  style={{ width: `${confidence}%` }}
                />
              </div>
              <span className="font-mono text-xs font-semibold text-cyan-300">{confidence}%</span>
            </div>
            <p className="text-[10px] text-slate-500 mt-1 leading-snug">
              Based on parsed security attributes, matching indicators, and registrar records.
            </p>
          </div>

          <div className="flex gap-2 text-slate-300 text-[11px] items-center bg-slate-900/20 p-2 rounded border border-slate-800/40">
            <Activity className="w-3.5 h-3.5 text-cyan-500 shrink-0" />
            <span>
              Heuristic validation reports <span className="text-white font-semibold">{factors.length}</span> active evaluation factors.
            </span>
          </div>
        </div>
      </div>

      {/* Structured Evaluation breakdown list */}
      <h4 className="font-mono text-[10px] font-medium uppercase tracking-wider text-slate-400 border-t border-slate-800/80 pt-4 mt-4 mb-2">
        Active Risk Factors Checklist
      </h4>
      <div className="space-y-2 max-h-56 overflow-y-auto pr-1">
        {factors.map((factor, index) => (
          <div 
            key={index} 
            className="flex items-start gap-2.5 p-2 rounded bg-slate-900/50 border border-slate-800/80 hover:bg-slate-950/50 transition-colors"
          >
            {factor.isNegative ? (
              <ShieldAlert className="w-4 h-4 text-rose-500 shrink-0 mt-0.5" />
            ) : (
              <ShieldCheck className="w-4 h-4 text-emerald-500 shrink-0 mt-0.5" />
            )}
            <div className="flex-1">
              <div className="flex items-center justify-between gap-2">
                <span className="font-sans font-medium text-xs text-white">{factor.name}</span>
                <span className={`font-mono text-[10px] font-semibold ${factor.isNegative ? "text-rose-400" : "text-emerald-400"}`}>
                  {factor.isNegative ? `+${factor.impact} Risk` : `-${factor.impact} Risk`}
                </span>
              </div>
              <p className="text-[10px] text-slate-400 mt-0.5 leading-relaxed">{factor.description}</p>
            </div>
          </div>
        ))}
        {factors.length === 0 && (
          <div className="text-center py-4 text-slate-500 text-xs font-mono">
            No dynamic risk multipliers isolated.
          </div>
        )}
      </div>
    </div>
  );
}
