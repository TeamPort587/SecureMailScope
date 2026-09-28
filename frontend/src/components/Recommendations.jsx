import React, { useState, useMemo } from 'react';
import RiskBadge from './RiskBadge';
import EmptyState from './EmptyState';
import {
  Lightbulb,
  CheckCircle2,
  Network,
  BookOpen,
  ChevronDown,
  ChevronUp,
  ChevronLeft,
  ChevronRight,
  Table,
  ArrowUpRight,
  Search,
} from 'lucide-react';

export default function Recommendations({
  recommendations = [],
  findings = [],
  sessions = [],
  onSelectSession,
  onFilterSessionsInTable = null,
}) {
  if (!recommendations || recommendations.length === 0) {
    return (
      <section className="w-full">
        <SectionHeader />

        <div className="mt-4">
          <EmptyState
            title="No Immediate Remediation Needed"
            message="The analyzed email traffic conforms to the expected cryptographic and transport security requirements."
            icon="secure"
          />
        </div>
      </section>
    );
  }

  return (
    <section className="w-full">
      <SectionHeader />

      <div className="mt-5 grid grid-cols-1 gap-4 lg:grid-cols-2">
        {recommendations.map((recommendation, index) => (
          <RecommendationCard
            key={
              recommendation?.recommendation_id ||
              `recommendation-${index}`
            }
            recommendation={recommendation}
            findings={findings}
            sessions={sessions}
            onSelectSession={onSelectSession}
            onFilterSessionsInTable={onFilterSessionsInTable}
          />
        ))}
      </div>
    </section>
  );
}

/* ---------------------------------------------------------
   Section Header
--------------------------------------------------------- */

function SectionHeader() {
  return (
    <div className="flex items-center gap-3">
      <div
        className="
          flex h-8 w-8 shrink-0
          items-center justify-center
          rounded-lg
          border border-yellow-200 dark:border-yellow-900/50
          bg-yellow-50 dark:bg-yellow-950/40
        "
      >
        <Lightbulb className="h-4 w-4 text-yellow-600 dark:text-yellow-400" />
      </div>

      <div>
        <h3 className="text-[15px] font-semibold text-slate-900 dark:text-white">
          Remediation & Hardening
        </h3>

        <p className="mt-0.5 text-xs leading-5 text-slate-500 dark:text-slate-400">
          Actions required to address the security weaknesses observed in this capture.
        </p>
      </div>
    </div>
  );
}

/* ---------------------------------------------------------
   Recommendation Card
--------------------------------------------------------- */

function RecommendationCard({
  recommendation,
  findings = [],
  sessions = [],
  onSelectSession,
  onFilterSessionsInTable = null,
}) {
  const [isExpanded, setIsExpanded] = useState(false);
  const [drawerSearch, setDrawerSearch] = useState('');
  const [drawerPage, setDrawerPage] = useState(1);

  const priority = (
    recommendation?.priority || 'INFO'
  ).toUpperCase();

  const affectedSessions = useMemo(
    () => getAffectedSessions(recommendation, findings),
    [recommendation, findings]
  );

  const SAMPLE_LIMIT = 4;
  const hasMore = affectedSessions.length > SAMPLE_LIMIT;
  const sampleChips = affectedSessions.slice(0, SAMPLE_LIMIT);

  const filteredDrawerSessions = useMemo(() => {
    if (!drawerSearch.trim()) return affectedSessions;
    const q = drawerSearch.toLowerCase().trim();
    return affectedSessions.filter((sId) => sId.toLowerCase().includes(q));
  }, [affectedSessions, drawerSearch]);

  const DRAWER_PAGE_SIZE = 10;
  const totalDrawerPages = Math.ceil(filteredDrawerSessions.length / DRAWER_PAGE_SIZE) || 1;
  const paginatedDrawerSessions = useMemo(() => {
    const start = (drawerPage - 1) * DRAWER_PAGE_SIZE;
    return filteredDrawerSessions.slice(start, start + DRAWER_PAGE_SIZE);
  }, [filteredDrawerSessions, drawerPage]);

  const handleOpenFilteredSessions = (e) => {
    if (e) e.stopPropagation();
    onFilterSessionsInTable?.({
      title: recommendation?.title || 'Security Recommendation',
      sessionIds: affectedSessions,
    });
  };

  const styles = {
    CRITICAL: {
      accent: 'bg-red-500',
      tint: 'from-red-50/35 via-white to-white dark:from-red-950/30 dark:via-slate-900 dark:to-slate-900',

      actionBg: 'bg-red-50/55 dark:bg-red-950/30',
      actionBorder: 'border-red-200 dark:border-red-900/50',
      actionIcon: 'border-red-200 bg-white text-red-600 dark:border-red-900/60 dark:bg-slate-800 dark:text-red-400',
      actionLabel: 'text-red-700 dark:text-red-400',
    },

    HIGH: {
      accent: 'bg-orange-500',
      tint: 'from-orange-50/30 via-white to-white dark:from-orange-950/30 dark:via-slate-900 dark:to-slate-900',

      actionBg: 'bg-orange-50/50 dark:bg-orange-950/30',
      actionBorder: 'border-orange-200 dark:border-orange-900/50',
      actionIcon: 'border-orange-200 bg-white text-orange-600 dark:border-orange-900/60 dark:bg-slate-800 dark:text-orange-400',
      actionLabel: 'text-orange-700 dark:text-orange-400',
    },

    MEDIUM: {
      accent: 'bg-amber-500',
      tint: 'from-amber-50/25 via-white to-white dark:from-amber-950/30 dark:via-slate-900 dark:to-slate-900',

      actionBg: 'bg-amber-50/45 dark:bg-amber-950/30',
      actionBorder: 'border-amber-200 dark:border-amber-900/50',
      actionIcon: 'border-amber-200 bg-white text-amber-600 dark:border-amber-900/60 dark:bg-slate-800 dark:text-amber-400',
      actionLabel: 'text-amber-700 dark:text-amber-400',
    },

    LOW: {
      accent: 'bg-yellow-500',
      tint: 'from-yellow-50/25 via-white to-white dark:from-yellow-950/30 dark:via-slate-900 dark:to-slate-900',

      actionBg: 'bg-yellow-50/45 dark:bg-yellow-950/30',
      actionBorder: 'border-yellow-200 dark:border-yellow-900/50',
      actionIcon: 'border-yellow-200 bg-white text-yellow-600 dark:border-yellow-900/60 dark:bg-slate-800 dark:text-yellow-400',
      actionLabel: 'text-yellow-700 dark:text-yellow-400',
    },

    INFO: {
      accent: 'bg-blue-500',
      tint: 'from-blue-50/25 via-white to-white dark:from-blue-950/30 dark:via-slate-900 dark:to-slate-900',

      actionBg: 'bg-blue-50/40 dark:bg-blue-950/30',
      actionBorder: 'border-blue-200 dark:border-blue-900/50',
      actionIcon: 'border-blue-200 bg-white text-blue-600 dark:border-blue-900/60 dark:bg-slate-800 dark:text-blue-400',
      actionLabel: 'text-blue-700 dark:text-blue-400',
    },
  };

  const style = styles[priority] || styles.INFO;

  return (
    <article
      className="
        group relative overflow-hidden
        rounded-xl
        border border-slate-200 dark:border-slate-800
        bg-white dark:bg-slate-900
        shadow-[0_2px_10px_rgba(15,23,42,0.025)] dark:shadow-[0_2px_10px_rgba(0,0,0,0.3)]
        transition-all duration-200
        hover:border-slate-300 dark:hover:border-slate-700
        hover:shadow-[0_6px_20px_rgba(15,23,42,0.05)]
      "
    >
      {/* Severity accent */}
      <div
        className={`absolute inset-y-0 left-0 w-[3px] ${style.accent}`}
      />

      <div
        className={`
          bg-gradient-to-br
          ${style.tint}
          px-5 py-5 pl-6
        `}
      >
        {/* Header */}
        <div className="flex items-center justify-between gap-4">
          <RiskBadge
            level={priority}
            size="sm"
          />

          {recommendation?.recommendation_id && (
            <span
              className="
                rounded-md
                border border-slate-200 dark:border-slate-700
                bg-white/75 dark:bg-slate-800/80
                px-2 py-1
                font-mono
                text-[10px]
                font-medium
                text-slate-500 dark:text-slate-400
              "
            >
              {recommendation.recommendation_id}
            </span>
          )}
        </div>

        {/* Title */}
        <h4
          className="
            mt-4
            text-[16px]
            font-semibold
            leading-6
            text-slate-900 dark:text-white
          "
        >
          {recommendation?.title ||
            'Security hardening recommendation'}
        </h4>

        {/* Description */}
        {recommendation?.description && (
          <p
            className="
              mt-2
              max-w-3xl
              text-sm
              leading-6
              text-slate-600 dark:text-slate-300
            "
          >
            {recommendation.description}
          </p>
        )}

        {/* Standards Guidance Reference */}
        {(() => {
          const text = `${recommendation?.title || ''} ${recommendation?.description || ''}`.toLowerCase();
          let guidance = null;
          if (text.includes('tls 1.0') || text.includes('tls 1.1')) {
            guidance = { doc: 'RFC 8996', note: 'TLS 1.0 & 1.1 are formally deprecated; modern negotiation requires TLS 1.2+.' };
          } else if (text.includes('tls 1.3') || text.includes('tls 1.2') || text.includes('pfs') || text.includes('cipher')) {
            guidance = { doc: 'RFC 9325', note: 'IETF guidance prefers TLS 1.3 with AEAD and PFS; TLS 1.2 is an acceptable baseline.' };
          } else if (text.includes('cleartext') || text.includes('plaintext') || text.includes('starttls') || text.includes('implicit')) {
            guidance = { doc: 'RFC 8314', note: 'Cleartext email submission/access is obsolete; Implicit TLS is preferred.' };
          } else if (text.includes('certificate') || text.includes('rsa') || text.includes('key')) {
            guidance = { doc: 'NIST SP 800-52 / 57', note: 'NIST key management requires ≥ 2048-bit RSA or equivalent curves.' };
          }

          if (!guidance) return null;

          return (
            <div className="mt-3 flex items-center gap-2 rounded-lg border border-sky-200/80 dark:border-sky-900/50 bg-sky-50/60 dark:bg-sky-950/40 px-3 py-1.5 text-xs text-sky-900 dark:text-sky-200">
              <BookOpen className="h-3.5 w-3.5 text-sky-600 dark:text-sky-400 shrink-0" />
              <div className="flex flex-wrap items-center gap-1.5">
                <span className="font-mono font-bold text-sky-800 dark:text-sky-300">{guidance.doc}:</span>
                <span className="text-sky-700 dark:text-sky-300">{guidance.note}</span>
              </div>
            </div>
          );
        })()}

        {/* Affected / Target Sessions */}
        <div className="mt-4 pt-3.5 border-t border-slate-200/60 dark:border-slate-800">
          <div className="flex items-center justify-between gap-2 mb-2">
            <span className="text-[11px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 flex items-center gap-1.5">
              <Network className="h-3.5 w-3.5 text-slate-400 dark:text-slate-500" />
              Impacted Sessions
            </span>
            <div className="flex items-center gap-2">
              {affectedSessions.length > 0 && (
                <span className="text-[11px] font-medium text-slate-400 dark:text-slate-500">
                  {affectedSessions.length === 1
                    ? '1 session affected'
                    : `${affectedSessions.length} sessions affected`}
                </span>
              )}
              {affectedSessions.length > SAMPLE_LIMIT && onFilterSessionsInTable && (
                <button
                  type="button"
                  onClick={handleOpenFilteredSessions}
                  className="inline-flex items-center gap-1 rounded-md border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 px-2 py-0.5 text-[10px] font-semibold text-brand-600 dark:text-brand-400 hover:text-brand-700 dark:hover:text-brand-300 transition shadow-2xs"
                  title="View all affected sessions in Sessions table"
                >
                  <Table className="h-3 w-3" />
                  <span>Open in table</span>
                  <ArrowUpRight className="h-3 w-3" />
                </button>
              )}
            </div>
          </div>

          {/* Sample Chips Row */}
          <div className="flex flex-wrap items-center gap-1.5">
            {affectedSessions.length > 0 ? (
              <>
                {sampleChips.map((sessionId) => (
                  <SessionChip
                    key={sessionId}
                    sessionId={sessionId}
                    sessions={sessions}
                    onSelectSession={onSelectSession}
                  />
                ))}

                {hasMore && (
                  <button
                    type="button"
                    onClick={() => setIsExpanded(!isExpanded)}
                    className={`inline-flex items-center gap-1 rounded-lg border px-2 py-1 text-[11px] font-semibold transition-all ${
                      isExpanded
                        ? 'border-brand-300 dark:border-brand-700 bg-brand-50 dark:bg-brand-950/60 text-brand-700 dark:text-brand-300'
                        : 'border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 text-slate-600 dark:text-slate-300 hover:border-brand-300 hover:text-brand-600'
                    }`}
                  >
                    <span>
                      {isExpanded ? 'Hide' : `+${affectedSessions.length - SAMPLE_LIMIT} more`}
                    </span>
                    {isExpanded ? (
                      <ChevronUp className="h-3 w-3" />
                    ) : (
                      <ChevronDown className="h-3 w-3" />
                    )}
                  </button>
                )}
              </>
            ) : (
              <span className="inline-flex items-center gap-1 text-xs text-slate-400 italic">
                General hygiene policy (applies across all sessions)
              </span>
            )}
          </div>

          {/* Expandable Mini-Drawer */}
          {isExpanded && hasMore && (
            <div className="mt-3 rounded-xl border border-slate-200 dark:border-slate-700 bg-slate-50/70 dark:bg-slate-850/60 p-3.5 animate-in fade-in slide-in-from-top-1 duration-150">
              <div className="mb-2.5 flex items-center justify-between gap-2">
                <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                  All Impacted Sessions ({affectedSessions.length})
                </span>

                {affectedSessions.length > 6 && (
                  <div className="relative w-36">
                    <Search className="pointer-events-none absolute left-2 top-1/2 h-3 w-3 -translate-y-1/2 text-slate-400" />
                    <input
                      type="text"
                      placeholder="Search..."
                      value={drawerSearch}
                      onChange={(e) => {
                        setDrawerSearch(e.target.value);
                        setDrawerPage(1);
                      }}
                      className="h-6.5 w-full rounded-md border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 pl-6 pr-2 text-[10px] text-slate-700 dark:text-slate-200 placeholder:text-slate-400 focus:border-brand-500 focus:outline-none"
                    />
                  </div>
                )}
              </div>

              <div className="flex flex-wrap items-center gap-1.5">
                {paginatedDrawerSessions.map((sessionId) => (
                  <SessionChip
                    key={sessionId}
                    sessionId={sessionId}
                    sessions={sessions}
                    onSelectSession={onSelectSession}
                  />
                ))}
              </div>

              {filteredDrawerSessions.length > DRAWER_PAGE_SIZE && (
                <div className="mt-2.5 flex items-center justify-between border-t border-slate-200/60 dark:border-slate-800 pt-2 text-[10px] text-slate-500 dark:text-slate-400">
                  <span>
                    {(drawerPage - 1) * DRAWER_PAGE_SIZE + 1}–{Math.min(drawerPage * DRAWER_PAGE_SIZE, filteredDrawerSessions.length)} of {filteredDrawerSessions.length}
                  </span>

                  <div className="flex items-center gap-1">
                    <button
                      type="button"
                      disabled={drawerPage <= 1}
                      onClick={() => setDrawerPage((p) => Math.max(1, p - 1))}
                      className="inline-flex items-center rounded border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 px-1.5 py-0.5 text-[10px] font-medium disabled:opacity-40 cursor-pointer disabled:cursor-not-allowed hover:bg-slate-50 dark:hover:bg-slate-800 transition"
                      aria-label="Previous sessions page"
                    >
                      <ChevronLeft className="h-2.5 w-2.5" />
                    </button>
                    <span className="font-mono px-1">
                      {drawerPage}/{totalDrawerPages}
                    </span>
                    <button
                      type="button"
                      disabled={drawerPage >= totalDrawerPages}
                      onClick={() => setDrawerPage((p) => Math.min(totalDrawerPages, p + 1))}
                      className="inline-flex items-center rounded border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 px-1.5 py-0.5 text-[10px] font-medium disabled:opacity-40 cursor-pointer disabled:cursor-not-allowed hover:bg-slate-50 dark:hover:bg-slate-800 transition"
                      aria-label="Next sessions page"
                    >
                      <ChevronRight className="h-2.5 w-2.5" />
                    </button>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Required action */}
        <RequiredAction
          style={style}
          recommendation={recommendation}
        />
      </div>
    </article>
  );
}

/* ---------------------------------------------------------
   Helper: Extract or correlate affected session IDs
--------------------------------------------------------- */
export function getAffectedSessions(recommendation, findings = []) {
  if (Array.isArray(recommendation?.affected_sessions) && recommendation.affected_sessions.length > 0) {
    return recommendation.affected_sessions;
  }

  const recId = (recommendation?.recommendation_id || '').toUpperCase();
  const title = (recommendation?.title || '').toLowerCase();
  const desc = (recommendation?.description || '').toLowerCase();

  const matched = new Set();
  for (const f of findings) {
    const fType = (f?.finding_type || '').toUpperCase();
    const fTitle = (f?.title || '').toLowerCase();
    const fDesc = (f?.description || '').toLowerCase();

    const isMatch =
      // By recommendation ID
      (recId.includes('AUTH') && (fType.includes('AUTH') || fTitle.includes('auth'))) ||
      (recId.includes('PLAIN') && (fType.includes('PLAIN') || fTitle.includes('plain'))) ||
      (recId.includes('STARTTLS') && (fType.includes('STARTTLS') || fTitle.includes('starttls'))) ||
      (recId.includes('WEAK-TLS') && (fType.includes('DEPRECATED_TLS') || fType.includes('WEAK_TLS') || fTitle.includes('tls'))) ||
      (recId.includes('PFS') && (fType.includes('PFS') || fTitle.includes('forward secrecy'))) ||
      (recId.includes('CERT') && (fType.includes('CERT') || fTitle.includes('cert'))) ||
      (recId.includes('CIPHER') && (fType.includes('CIPHER') || fTitle.includes('cipher'))) ||
      (recId.includes('KEY') && (fType.includes('KEY') || fTitle.includes('key'))) ||
      // By title keywords
      (title.includes('authentication') && (fTitle.includes('auth') || fDesc.includes('auth'))) ||
      (title.includes('plaintext') && (fTitle.includes('plaintext') || fDesc.includes('plaintext'))) ||
      (title.includes('starttls') && (fTitle.includes('starttls') || fDesc.includes('starttls'))) ||
      (title.includes('cipher') && (fTitle.includes('cipher') || fDesc.includes('cipher'))) ||
      (title.includes('certificate') && (fTitle.includes('cert') || fDesc.includes('cert'))) ||
      (title.includes('forward secrecy') && (fTitle.includes('forward secrecy') || fDesc.includes('pfs'))) ||
      (title.includes('renegotiation') && (fTitle.includes('renegotiation') || fDesc.includes('renegotiation')));

    if (isMatch && f.session_id) {
      matched.add(f.session_id);
    }
  }

  return Array.from(matched);
}

/* ---------------------------------------------------------
   Impacted Session Chip Component
--------------------------------------------------------- */
function SessionChip({ sessionId, sessions = [], onSelectSession }) {
  const sessionObj = sessions.find((s) => s.session_id === sessionId);
  const proto = (
    sessionObj?.protocol ||
    (sessionId.toLowerCase().startsWith('smtp')
      ? 'SMTP'
      : sessionId.toLowerCase().startsWith('imap')
      ? 'IMAP'
      : sessionId.toLowerCase().startsWith('pop')
      ? 'POP3'
      : 'TCP')
  ).toUpperCase();

  const protoTheme = {
    SMTP: {
      badge: 'border-blue-300/80 dark:border-blue-700/80 bg-blue-50/90 dark:bg-blue-950/80 text-blue-700 dark:text-blue-300',
      dot: 'bg-blue-500 dark:bg-blue-400',
    },
    IMAP: {
      badge: 'border-purple-300/80 dark:border-purple-700/80 bg-purple-50/90 dark:bg-purple-950/80 text-purple-700 dark:text-purple-300',
      dot: 'bg-purple-500 dark:bg-purple-400',
    },
    POP3: {
      badge: 'border-emerald-300/80 dark:border-emerald-700/80 bg-emerald-50/90 dark:bg-emerald-950/80 text-emerald-700 dark:text-emerald-300',
      dot: 'bg-emerald-500 dark:bg-emerald-400',
    },
  }[proto] || {
    badge: 'border-slate-300/80 dark:border-slate-700 bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300',
    dot: 'bg-slate-400',
  };

  return (
    <button
      key={sessionId}
      type="button"
      onClick={() => onSelectSession?.(sessionId)}
      className="group/chip inline-flex items-center gap-1.5 rounded-lg border border-slate-200/90 dark:border-slate-700/90 bg-white/90 dark:bg-slate-850 px-2.5 py-1 text-xs shadow-2xs hover:border-brand-400 dark:hover:border-brand-500 hover:bg-brand-50/50 dark:hover:bg-slate-800 transition-all duration-150 cursor-pointer"
      title={`Click to inspect session ${sessionId}`}
    >
      <span
        className={`inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[9px] font-bold font-sans uppercase tracking-wider border ${protoTheme.badge}`}
      >
        <span className={`h-1.5 w-1.5 rounded-full ${protoTheme.dot}`} />
        {proto}
      </span>
      <span className="font-mono text-[11px] font-semibold text-slate-800 dark:text-slate-100 group-hover/chip:text-brand-600 dark:group-hover/chip:text-brand-400 transition-colors">
        {sessionId}
      </span>
    </button>
  );
}

/* ---------------------------------------------------------
   Required Action Component
--------------------------------------------------------- */

function RequiredAction({
  style,
  recommendation,
}) {
  return (
    <div
      className={`
        mt-5
        rounded-lg
        border
        ${style.actionBorder}
        ${style.actionBg}
        px-3.5 py-3
      `}
    >
      <div className="flex items-center gap-3">
        {/* Action status icon */}
        <div
          className={`
            flex h-8 w-8 shrink-0
            items-center justify-center
            rounded-lg
            border
            ${style.actionIcon}
          `}
        >
          <CheckCircle2 className="h-4 w-4" />
        </div>

        {/* Action content */}
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span
              className={`
                text-[10px]
                font-bold
                uppercase
                tracking-[0.1em]
                ${style.actionLabel}
              `}
            >
              Required action
            </span>

            <span
              className="
                rounded
                border border-slate-200/80 dark:border-slate-700
                bg-white/70 dark:bg-slate-800/70
                px-1.5 py-0.5
                text-[8px]
                font-bold
                uppercase
                tracking-wider
                text-slate-400
              "
            >
              Required
            </span>
          </div>

          <p
            className="
              mt-1
              text-[13px]
              font-semibold
              leading-5
              text-slate-800 dark:text-slate-200
            "
          >
            {recommendation?.action ||
              'Apply the relevant MTA or client security policy.'}
          </p>
        </div>
      </div>
    </div>
  );
}