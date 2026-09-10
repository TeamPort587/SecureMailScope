import React from 'react';
import RiskBadge from './RiskBadge';
import EmptyState from './EmptyState';
import { Lightbulb, CheckCircle2 } from 'lucide-react';

export default function Recommendations({
  recommendations = [],
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

function RecommendationCard({ recommendation }) {
  const priority = (
    recommendation?.priority || 'INFO'
  ).toUpperCase();

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