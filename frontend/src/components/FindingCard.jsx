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
  ArrowUpRight,
} from "lucide-react";

export default function FindingCard({ finding, onSelectSession = null }) {
  const [showEvidence, setShowEvidence] = useState(false);

  const handleSessionRedirect = (e) => {
    if (e) e.stopPropagation();
    if (!finding?.session_id) return;

    if (onSelectSession) {
      onSelectSession(finding.session_id);
      return;
    }

    // Fallback if rendered without onSelectSession prop
    if (typeof window !== "undefined") {
      const match = window.location.pathname.match(/\/analysis\/([^/]+)/);
      if (match) {
        window.location.href = `/analysis/${match[1]}/session/${finding.session_id}`;
      }
    }
  };

  const severity = (finding?.severity || "INFO").toUpperCase();

  const severityStyles = {
    CRITICAL: {
      accent: "bg-red-500",
      icon: "border-red-200 dark:border-red-900/60 bg-red-50 dark:bg-red-950/40 text-red-600 dark:text-red-400",
      soft: "bg-red-50/50 dark:bg-red-950/30",
      border: "border-red-200 dark:border-red-900/50",
    },
    HIGH: {
      accent: "bg-orange-500",
      icon: "border-orange-200 dark:border-orange-900/60 bg-orange-50 dark:bg-orange-950/40 text-orange-600 dark:text-orange-400",
      soft: "bg-orange-50/50 dark:bg-orange-950/30",
      border: "border-orange-200 dark:border-orange-900/50",
    },
    MEDIUM: {
      accent: "bg-amber-500",
      icon: "border-amber-200 dark:border-amber-900/60 bg-amber-50 dark:bg-amber-950/40 text-amber-600 dark:text-amber-400",
      soft: "bg-amber-50/50 dark:bg-amber-950/30",
      border: "border-amber-200 dark:border-amber-900/50",
    },
    LOW: {
      accent: "bg-yellow-500",
      icon: "border-yellow-200 dark:border-yellow-900/60 bg-yellow-50 dark:bg-yellow-950/40 text-yellow-600 dark:text-yellow-400",
      soft: "bg-yellow-50/50 dark:bg-yellow-950/30",
      border: "border-yellow-200 dark:border-yellow-900/50",
    },
    INFO: {
      accent: "bg-blue-500",
      icon: "border-blue-200 dark:border-blue-900/60 bg-blue-50 dark:bg-blue-950/40 text-blue-600 dark:text-blue-400",
      soft: "bg-blue-50/50 dark:bg-blue-950/30",
      border: "border-blue-200 dark:border-blue-900/50",
    },
  };

  const style = severityStyles[severity] || severityStyles.INFO;

  const evidenceCount = finding?.evidence
  ? Object.keys(finding.evidence).length
  : 0;

  return (
    <article
      className="
        group relative overflow-hidden
        rounded-xl border border-slate-200 dark:border-slate-800
        bg-white dark:bg-slate-900
        shadow-[0_2px_10px_rgba(15,23,42,0.025)] dark:shadow-[0_2px_10px_rgba(0,0,0,0.3)]
        transition-all duration-200
        hover:border-slate-300 dark:hover:border-slate-700
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

            <h3 className="mt-3 text-[16px] font-semibold leading-6 text-slate-900 dark:text-white">
              {finding?.title || "Security finding detected"}
            </h3>

            {finding?.description && (
              <p className="mt-1.5 max-w-4xl text-sm leading-6 text-slate-600 dark:text-slate-300">
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
                items-center gap-2.5
                rounded-xl border
                px-3.5 py-2.5
                text-xs font-semibold
                transition-all duration-200
                sm:inline-flex
                ${
                  showEvidence
                    ? 'border-brand-200 dark:border-brand-800 bg-brand-50 dark:bg-brand-950/60 text-brand-700 dark:text-brand-300'
                    : `
                        border-slate-200 dark:border-slate-800
                        bg-slate-50 dark:bg-slate-850
                        text-slate-700 dark:text-slate-200
                        hover:border-brand-300 dark:hover:border-brand-700
                        hover:bg-brand-50/50 dark:hover:bg-brand-950/40
                        hover:text-brand-600 dark:hover:text-brand-300
                      `
                }
              `}
            >
              <div
                className={`
                  flex h-7 w-7 items-center justify-center
                  rounded-lg
                  ${
                    showEvidence
                      ? 'bg-brand-100 dark:bg-brand-900/60 text-brand-600 dark:text-brand-400'
                      : 'bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-700/60 text-slate-500 dark:text-slate-400'
                  }
                `}
              >
                <Terminal className="h-3.5 w-3.5" />
              </div>

              <div className="text-left">
                <p className="leading-4">
                  {showEvidence ? 'Evidence visible' : 'View evidence'}
                </p>

                {!showEvidence && evidenceCount > 0 && (
                  <p className="mt-0.5 text-[10px] font-normal text-slate-500 dark:text-slate-400">
                    {evidenceCount} supporting attributes
                  </p>
                )}
              </div>

              {showEvidence ? (
                <ChevronUp className="ml-1 h-3.5 w-3.5 text-brand-500 dark:text-brand-400" />
              ) : (
                <ChevronDown className="ml-1 h-3.5 w-3.5 text-slate-400 dark:text-slate-500" />
              )}
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
                  ? `${style.border} ${style.soft} text-slate-800 dark:text-slate-200`
                  : "border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-850 text-slate-700 dark:text-slate-200"
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
            border-t border-slate-100 dark:border-slate-800
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
            />
          )}

          {finding?.session_id && (
            <MetadataCard
              icon={Network}
              label="Session"
              value={finding.session_id}
              mono
              isClickable={Boolean(onSelectSession || finding?.session_id)}
              onClick={handleSessionRedirect}
              title={`Click to inspect session ${finding.session_id}`}
              actionHint="Inspect"
            />
          )}

          {finding?.confidence && (
            <MetadataCard
              icon={Activity}
              label="Confidence"
              value={finding.confidence}
            />
          )}
        </div>
      </div>

      {/* Evidence panel */}
      {showEvidence && (
  <div
    className="
      border-t border-slate-100 dark:border-slate-800
      px-5 py-5
      pl-6
      sm:px-6
      animate-in fade-in slide-in-from-top-1 duration-200
    "
  >
    <div className="mb-3 flex items-center justify-between">
      <div>
        <p className="text-sm font-semibold text-slate-800 dark:text-white">
          Technical evidence
        </p>

        <p className="mt-0.5 text-[11px] text-slate-500 dark:text-slate-400">
          Supporting attributes extracted during session inspection
        </p>
      </div>

      <span className="rounded-full border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 px-2.5 py-1 text-[10px] font-medium text-slate-500 dark:text-slate-400">
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
  onClick = null,
  isClickable = false,
  actionHint = null,
  title = null,
}) {
  const Component = isClickable ? "button" : "div";

  return (
    <Component
      type={isClickable ? "button" : undefined}
      onClick={onClick}
      title={title || (isClickable ? `Click to inspect ${value}` : undefined)}
      className={`
        group/meta flex min-h-[66px] w-full
        items-center justify-between gap-3
        rounded-lg
        border border-slate-200 dark:border-slate-800
        border-l-[3px] border-l-brand-400 dark:border-l-brand-500
        bg-slate-50 dark:bg-slate-850
        px-3.5 py-3
        text-left
        transition-all duration-200
        ${
          isClickable
            ? `cursor-pointer
               hover:border-slate-300 dark:hover:border-slate-700
               hover:border-l-brand-500 dark:hover:border-l-brand-400
               hover:bg-slate-100/80 dark:hover:bg-slate-800/80
               hover:shadow-sm hover:scale-[1.01] active:scale-[0.99]`
            : `hover:border-slate-300 dark:hover:border-slate-700
               hover:border-l-brand-500 hover:shadow-sm`
        }
      `}
    >
      <div className="flex items-center gap-3 min-w-0">
        {/* Icon */}
        <div
          className={`
            flex h-9 w-9 shrink-0
            items-center justify-center
            rounded-lg
            border border-slate-200 dark:border-slate-700/60
            bg-white dark:bg-slate-900
            shadow-sm transition-colors
            ${
              isClickable
                ? "group-hover/meta:border-brand-300 dark:group-hover/meta:border-brand-500 group-hover/meta:bg-brand-50 dark:group-hover/meta:bg-brand-950/60"
                : ""
            }
          `}
        >
          <Icon
            className={`h-4 w-4 transition-colors ${
              isClickable
                ? "text-slate-500 dark:text-slate-400 group-hover/meta:text-brand-600 dark:group-hover/meta:text-brand-400"
                : "text-slate-500 dark:text-slate-400"
            }`}
          />
        </div>

        {/* Content */}
        <div className="min-w-0">
          <p
            className="
              text-[11px]
              font-bold
              uppercase
              tracking-[0.08em]
              text-slate-500 dark:text-slate-400
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
              text-slate-900 dark:text-white
              ${mono ? "font-mono" : ""}
              ${
                isClickable
                  ? "group-hover/meta:text-brand-600 dark:group-hover/meta:text-brand-400"
                  : ""
              }
            `}
            title={value}
          >
            {value}
          </p>
        </div>
      </div>

      {/* Redirect Indicator */}
      {isClickable && (
        <div className="flex shrink-0 items-center gap-1 rounded-md px-2 py-1 text-[11px] font-semibold text-brand-600 dark:text-brand-400 group-hover/meta:bg-brand-50 dark:group-hover/meta:bg-brand-950/60 transition-all">
          <span className="hidden sm:inline text-[10px] font-sans font-bold uppercase tracking-wider">
            {actionHint || "Inspect"}
          </span>
          <ArrowUpRight className="h-3.5 w-3.5 transition-transform duration-200 group-hover/meta:-translate-y-0.5 group-hover/meta:translate-x-0.5" />
        </div>
      )}
    </Component>
  );
}