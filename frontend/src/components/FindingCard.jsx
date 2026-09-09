import React, { useState } from "react";
import RiskBadge from "./RiskBadge";
import EvidencePanel from "./EvidencePanel";

import {
  ChevronDown,
  ChevronUp,
  Terminal,
  ShieldAlert,
  Activity,
  Hash,
  Network,
} from "lucide-react";

export default function FindingCard({ finding }) {
  const [showEvidence, setShowEvidence] = useState(false);

  const severity = (finding?.severity || "INFO").toUpperCase();

  const severityStyles = {
    CRITICAL: {
      accent: "bg-red-500",
      icon: "border-red-200 bg-red-50 text-red-600",
      soft: "bg-red-50/50",
      border: "border-red-200",
    },
    HIGH: {
      accent: "bg-orange-500",
      icon: "border-orange-200 bg-orange-50 text-orange-600",
      soft: "bg-orange-50/50",
      border: "border-orange-200",
    },
    MEDIUM: {
      accent: "bg-amber-500",
      icon: "border-amber-200 bg-amber-50 text-amber-600",
      soft: "bg-amber-50/50",
      border: "border-amber-200",
    },
    LOW: {
      accent: "bg-yellow-500",
      icon: "border-yellow-200 bg-yellow-50 text-yellow-600",
      soft: "bg-yellow-50/50",
      border: "border-yellow-200",
    },
    INFO: {
      accent: "bg-blue-500",
      icon: "border-blue-200 bg-blue-50 text-blue-600",
      soft: "bg-blue-50/50",
      border: "border-blue-200",
    },
  };

  const style = severityStyles[severity] || severityStyles.INFO;

  const evidenceCount = finding?.evidence
  ? Object.keys(finding.evidence).length
  : 0;

  return (
    <div className={`rounded-xl border p-4 transition-all bg-white dark:bg-slate-900/60 border-slate-200 dark:border-slate-800 ${config.border} hover:bg-slate-50 dark:hover:bg-slate-900/80 shadow-sm`}>
      <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-3">
        {/* Finding Header */}
        <div className="space-y-1.5 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <RiskBadge level={finding.severity} size="sm" />
            <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-slate-700">
              Type: {finding.finding_type}
            </span>
            <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-brand-50 dark:bg-brand-500/10 text-brand-700 dark:text-brand-300 border border-brand-200 dark:border-brand-500/20 font-semibold">
              Session: {finding.session_id}
            </span>
            <span className="text-[11px] font-mono text-slate-500 dark:text-slate-400">
              Confidence: <strong className="text-slate-800 dark:text-slate-200">{finding.confidence || 'OBSERVED'}</strong>
            </span>
          </div>

          <h4 className="text-sm font-bold text-slate-900 dark:text-white tracking-tight">
            {finding.title}
          </h4>

          <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
            {finding.description}
          </p>
        </div>

        {/* Mobile evidence */}
        {finding?.evidence && (
          <button
            type="button"
            onClick={() => setShowEvidence(!showEvidence)}
            className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors shrink-0 ${
              showEvidence
                ? 'bg-brand-50 dark:bg-brand-500/20 text-brand-700 dark:text-brand-300 border-brand-300 dark:border-brand-500/40'
                : 'bg-slate-100 dark:bg-slate-800/80 hover:bg-slate-200 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300 border-slate-200 dark:border-slate-700'
            }`}
            aria-expanded={showEvidence}
            className={`
              mt-4 flex w-full
              items-center justify-center gap-2
              rounded-lg border
              px-3 py-2
              text-xs font-semibold
              sm:hidden
              ${
                showEvidence
                  ? `${style.border} ${style.soft} text-slate-800`
                  : "border-slate-200 bg-slate-50 text-slate-600"
              }
            `}
          >
            <Terminal className="w-3.5 h-3.5 text-brand-600 dark:text-brand-400" />
            <span>Evidence</span>
            {showEvidence ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
          </button>
        )}
      </div>

      {/* Metadata */}
      <div className="px-5 pb-5 pl-6 sm:px-6">
        <div
          className="
            grid grid-cols-1 gap-2
            border-t border-slate-100
            pt-4
            sm:grid-cols-2
            lg:grid-cols-3
          "
        >
          {finding?.finding_type && (
            <MetadataCard
              icon={Hash}
              label="Finding type"
              value={finding.finding_type}
              mono
              gradient="from-slate-100/70 via-white to-blue-50/70"
            />
          )}

          {finding?.session_id && (
            <MetadataCard
              icon={Network}
              label="Session"
              value={finding.session_id}
              mono
              gradient="from-slate-100/70 via-white to-blue-50/70"
            />
          )}

          {finding?.confidence && (
            <MetadataCard
              icon={Activity}
              label="Confidence"
              value={finding.confidence}
              gradient="from-slate-100/70 via-white to-blue-50/70"
            />
          )}
        </div>
      </div>

      {/* Evidence panel */}
      {showEvidence && (
  <div
    className="
      border-t border-slate-100
      px-5 py-5
      pl-6
      sm:px-6
      animate-in fade-in slide-in-from-top-1 duration-200
    "
  >
    <div className="mb-3 flex items-center justify-between">
      <div>
        <p className="text-sm font-semibold text-slate-800">
          Technical evidence
        </p>

        <p className="mt-0.5 text-[11px] text-slate-500">
          Supporting attributes extracted during session inspection
        </p>
      </div>

      <span className="rounded-full border border-slate-200 bg-slate-50 px-2.5 py-1 text-[10px] font-medium text-slate-500">
        {evidenceCount} attributes
      </span>
    </div>

    <EvidencePanel evidence={finding.evidence} />
  </div>
)}
    </article>
  );
}

/* ===============================================================
   METADATA CARD
=============================================================== */

function MetadataCard({
  icon: Icon,
  label,
  value,
  mono = false,
  gradient = "from-slate-100/80 via-white to-slate-50",
}) {
  return (
    <div
      className={`
    flex min-h-[66px]
    items-center gap-3
    rounded-lg
    border border-slate-200
    border-l-[3px] border-l-brand-400
    bg-gradient-to-br ${gradient}
    px-3.5 py-3
    transition-all duration-200
    hover:border-slate-300
    hover:border-l-brand-500
    hover:shadow-sm
  `}
    >
      {/* Icon */}
      <div
        className="
          flex h-9 w-9 shrink-0
          items-center justify-center
          rounded-lg
          border border-slate-200
          bg-white/90
          shadow-sm
        "
      >
        <Icon className="h-4 w-4 text-slate-500" />
      </div>

      {/* Content */}
      <div className="min-w-0">
        <p
          className="
            text-[11px]
            font-bold
            uppercase
            tracking-[0.08em]
            text-slate-500
          "
        >
          {label}
        </p>

        <p
          className={`
            mt-1
            truncate
            text-[13px]
            font-semibold
            leading-4
            text-slate-900
            ${mono ? "font-mono" : ""}
          `}
          title={value}
        >
          {value}
        </p>
      </div>
    </div>
  );
}
