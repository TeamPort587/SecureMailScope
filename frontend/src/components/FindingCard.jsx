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
      accent: "bg-emerald-500",
      icon: "border-emerald-200 bg-emerald-50 text-emerald-600",
      soft: "bg-emerald-50/50",
      border: "border-emerald-200",
    },
    INFO: {
      accent: "bg-blue-500",
      icon: "border-blue-200 bg-blue-50 text-blue-600",
      soft: "bg-blue-50/50",
      border: "border-blue-200",
    },
  };

  const style = severityStyles[severity] || severityStyles.INFO;

  return (
    <article
      className="
        group relative overflow-hidden
        rounded-xl border border-slate-200
        bg-white
        shadow-[0_2px_10px_rgba(15,23,42,0.025)]
        transition-all duration-200
        hover:border-slate-300
        hover:shadow-[0_6px_24px_rgba(15,23,42,0.055)]
      "
    >
      {/* Severity accent */}
      <div className={`absolute inset-y-0 left-0 w-1 ${style.accent}`} />

      {/* Main finding */}
      <div className="p-5 pl-6 sm:p-6">
        <div className="flex items-start gap-4">
          {/* Icon */}
          <div
            className={`
              flex h-10 w-10 shrink-0
              items-center justify-center
              rounded-xl border
              ${style.icon}
            `}
          >
            <ShieldAlert className="h-[18px] w-[18px]" />
          </div>

          {/* Content */}
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <RiskBadge level={severity} size="sm" />
            </div>

            <h3 className="mt-3 text-[16px] font-semibold leading-6 text-slate-900">
              {finding?.title || "Security finding detected"}
            </h3>

            {finding?.description && (
              <p className="mt-1.5 max-w-4xl text-sm leading-6 text-slate-600">
                {finding.description}
              </p>
            )}
          </div>

          {/* Evidence */}
          {finding?.evidence && (
            <button
              type="button"
              onClick={() => setShowEvidence(!showEvidence)}
              aria-expanded={showEvidence}
              className={`
                hidden shrink-0
                items-center gap-2
                rounded-lg border
                px-3 py-2
                text-xs font-semibold
                transition-all
                sm:inline-flex
                ${
                  showEvidence
                    ? `${style.border} ${style.soft} text-slate-800`
                    : "border-slate-200 bg-white text-slate-600 hover:border-slate-300 hover:bg-slate-50 hover:text-slate-900"
                }
              `}
            >
              <Terminal
                className={`h-3.5 w-3.5 ${
                  showEvidence ? "text-slate-700" : "text-slate-400"
                }`}
              />

              <span>{showEvidence ? "Hide evidence" : "View evidence"}</span>

              <span className="ml-0.5 flex h-5 w-5 items-center justify-center rounded-md bg-slate-50">
                {showEvidence ? (
                  <ChevronUp className="h-3 w-3 text-slate-500" />
                ) : (
                  <ChevronDown className="h-3 w-3 text-slate-500" />
                )}
              </span>
            </button>
          )}
        </div>

        {/* Mobile evidence */}
        {finding?.evidence && (
          <button
            type="button"
            onClick={() => setShowEvidence(!showEvidence)}
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
            <Terminal className="h-3.5 w-3.5" />

            {showEvidence ? "Hide evidence" : "View evidence"}

            {showEvidence ? (
              <ChevronUp className="h-3.5 w-3.5" />
            ) : (
              <ChevronDown className="h-3.5 w-3.5" />
            )}
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
        <div className="border-t border-slate-100 bg-slate-50/40 p-5 sm:p-6">
          <div className="overflow-hidden rounded-xl border border-slate-200 bg-white">
            <div className="flex items-center gap-3 border-b border-slate-100 px-4 py-3">
              <div className="flex h-7 w-7 items-center justify-center rounded-lg border border-slate-200 bg-slate-50">
                <Terminal className="h-3.5 w-3.5 text-slate-500" />
              </div>

              <div>
                <p className="text-xs font-semibold text-slate-800">Evidence</p>

                <p className="mt-0.5 text-[10px] text-slate-500">
                  Supporting traffic observed in the capture
                </p>
              </div>
            </div>

            <div className="p-4">
              <EvidencePanel evidence={finding.evidence} />
            </div>
          </div>
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
