import React from 'react';
import RiskBadge from './RiskBadge';
import EmptyState from './EmptyState';
import { Lightbulb, CheckCircle2, Network } from 'lucide-react';

export default function Recommendations({
  recommendations = [],
  findings = [],
  sessions = [],
  onSelectSession,
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
          border border-yellow-200
          bg-yellow-50
        "
      >
        <Lightbulb className="h-4 w-4 text-yellow-600" />
      </div>

      <div>
        <h3 className="text-[15px] font-semibold text-slate-900">
          Remediation & Hardening
        </h3>

        <p className="mt-0.5 text-xs leading-5 text-slate-500">
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
}) {
  const priority = (
    recommendation?.priority || 'INFO'
  ).toUpperCase();

  const affectedSessions = getAffectedSessions(recommendation, findings);

  const styles = {
    CRITICAL: {
      accent: 'bg-red-500',
      tint: 'from-red-50/35 via-white to-white',

      actionBg: 'bg-red-50/55',
      actionBorder: 'border-red-200',
      actionIcon: 'border-red-200 bg-white text-red-600',
      actionLabel: 'text-red-700',
    },

    HIGH: {
      accent: 'bg-orange-500',
      tint: 'from-orange-50/30 via-white to-white',

      actionBg: 'bg-orange-50/50',
      actionBorder: 'border-orange-200',
      actionIcon: 'border-orange-200 bg-white text-orange-600',
      actionLabel: 'text-orange-700',
    },

    MEDIUM: {
      accent: 'bg-amber-500',
      tint: 'from-amber-50/25 via-white to-white',

      actionBg: 'bg-amber-50/45',
      actionBorder: 'border-amber-200',
      actionIcon: 'border-amber-200 bg-white text-amber-600',
      actionLabel: 'text-amber-700',
    },

    LOW: {
      accent: 'bg-yellow-500',
      tint: 'from-yellow-50/25 via-white to-white',

      actionBg: 'bg-yellow-50/45',
      actionBorder: 'border-yellow-200',
      actionIcon: 'border-yellow-200 bg-white text-yellow-600',
      actionLabel: 'text-yellow-700',
    },

    INFO: {
      accent: 'bg-blue-500',
      tint: 'from-blue-50/25 via-white to-white',

      actionBg: 'bg-blue-50/40',
      actionBorder: 'border-blue-200',
      actionIcon: 'border-blue-200 bg-white text-blue-600',
      actionLabel: 'text-blue-700',
    },
  };

  const style = styles[priority] || styles.INFO;

  return (
    <article
      className="
        group relative overflow-hidden
        rounded-xl
        border border-slate-200
        bg-white
        shadow-[0_2px_10px_rgba(15,23,42,0.025)]
        transition-all duration-200
        hover:border-slate-300
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
                border border-slate-200
                bg-white/75
                px-2 py-1
                font-mono
                text-[10px]
                font-medium
                text-slate-500
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
            text-slate-900
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
              text-slate-600
            "
          >
            {recommendation.description}
          </p>
        )}

        {/* Affected / Target Sessions */}
        <div className="mt-4 pt-3.5 border-t border-slate-200/60">
          <div className="flex items-center justify-between gap-2 mb-2">
            <span className="text-[11px] font-bold uppercase tracking-wider text-slate-500 flex items-center gap-1.5">
              <Network className="h-3.5 w-3.5 text-slate-400" />
              Impacted Sessions
            </span>
            {affectedSessions.length > 0 && (
              <span className="text-[11px] font-medium text-slate-400">
                {affectedSessions.length === 1
                  ? '1 session affected'
                  : `${affectedSessions.length} sessions affected`}
              </span>
            )}
          </div>

          <div className="flex flex-wrap items-center gap-1.5">
            {affectedSessions.length > 0 ? (
              affectedSessions.map((sessionId) => {
                const sessionObj = sessions.find((s) => s.session_id === sessionId);
                const proto =
                  sessionObj?.protocol ||
                  (sessionId.toLowerCase().startsWith('smtp')
                    ? 'SMTP'
                    : sessionId.toLowerCase().startsWith('imap')
                    ? 'IMAP'
                    : sessionId.toLowerCase().startsWith('pop')
                    ? 'POP3'
                    : 'TCP');

                return (
                  <button
                    key={sessionId}
                    type="button"
                    onClick={() => onSelectSession?.(sessionId)}
                    className="
                      group/chip inline-flex items-center gap-1.5
                      rounded-lg
                      border border-slate-200/90
                      bg-white
                      px-2.5 py-1
                      font-mono
                      text-[11px]
                      font-medium
                      text-slate-700
                      shadow-xs
                      hover:border-brand-400 hover:bg-brand-50/70 hover:text-brand-700
                      transition-all
                    "
                    title={`Click to inspect session ${sessionId}`}
                  >
                    <span className="h-1.5 w-1.5 rounded-full bg-amber-500 group-hover/chip:bg-brand-500 transition-colors" />
                    <span className="font-semibold text-[10px] text-slate-400 group-hover/chip:text-brand-600 font-sans uppercase">
                      {proto}
                    </span>
                    <span>{sessionId}</span>
                  </button>
                );
              })
            ) : (
              <span className="inline-flex items-center gap-1 text-xs text-slate-400 italic">
                General hygiene policy (applies across all sessions)
              </span>
            )}
          </div>
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
                border border-slate-200/80
                bg-white/70
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
              text-slate-800
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