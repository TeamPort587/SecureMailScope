import React from 'react';
import RiskBadge from './RiskBadge';

import {
  AlertTriangle,
  Layers,
  Bug,
  Unlock,
  LockKeyhole,
  Network,
  CheckCircle2,
} from 'lucide-react';

export default function RiskSummary({
  risk,
  summary,
  filename,
  uploadedAt,
}) {
  const riskLevel = (
    risk?.level || 'INFO'
  ).toUpperCase();

  const score =
    typeof risk?.score === 'number'
      ? Math.max(0, Math.min(100, Math.round(risk.score)))
      : 0;

  const confidence =
    typeof risk?.confidence === 'number'
      ? `${Math.round(risk.confidence * 100)}%`
      : '—';

  const totalSessions = summary?.total_sessions ?? 0;

  const smtp = summary?.smtp_sessions ?? 0;
  const imap = summary?.imap_sessions ?? 0;
  const pop3 = summary?.pop3_sessions ?? 0;

  const starttls = summary?.starttls_sessions ?? 0;
  const implicitTls = summary?.implicit_tls_sessions ?? 0;
  const plaintext = summary?.plaintext_sessions ?? 0;

  const riskContent = {
    CRITICAL: {
      title: 'Critical security exposure',
      description:
        'Immediate security exposure was detected. Plaintext authentication or unencrypted sensitive email traffic was observed.',
      accent: '#ef4444',
      soft: '#fee2e2',
      border: '#fecaca',
      text: '#b91c1c',
      panel:
        'border-red-200 bg-gradient-to-br from-red-50/70 via-white to-white',
    },

    HIGH: {
      title: 'High-risk security posture',
      description:
        'High-risk protocol weaknesses were identified, including downgrade or missing transport protection.',
      accent: '#f97316',
      soft: '#ffedd5',
      border: '#fed7aa',
      text: '#c2410c',
      panel:
        'border-orange-200 bg-gradient-to-br from-orange-50/70 via-white to-white',
    },

    MEDIUM: {
      title: 'Moderate security gaps',
      description:
        'Moderate security weaknesses were detected. Review encryption negotiation and legacy protocol usage.',
      accent: '#f59e0b',
      soft: '#fef3c7',
      border: '#fde68a',
      text: '#b45309',
      panel:
        'border-amber-200 bg-gradient-to-br from-amber-50/70 via-white to-white',
    },

    LOW: {
      title: 'Strong security posture',
      description:
        'Strong transport protection was observed with modern TLS negotiation and appropriate cryptographic controls.',
      accent: '#10b981',
      soft: '#d1fae5',
      border: '#a7f3d0',
      text: '#047857',
      panel:
        'border-emerald-200 bg-gradient-to-br from-emerald-50/70 via-white to-white',
    },

    INFO: {
      title: 'Security posture looks healthy',
      description:
        'The analyzed sessions meet the expected security requirements.',
      accent: '#3b82f6',
      soft: '#dbeafe',
      border: '#bfdbfe',
      text: '#1d4ed8',
      panel:
        'border-blue-200 bg-gradient-to-br from-blue-50/70 via-white to-white',
    },
  };

  const content =
    riskContent[riskLevel] || riskContent.INFO;

  const isHealthy =
    riskLevel === 'LOW' || riskLevel === 'INFO';

  return (
    <div className="w-full space-y-4">

      {/* =====================================================
          MAIN RISK OVERVIEW
      ====================================================== */}

      <section
        className={`relative overflow-hidden rounded-2xl border ${content.panel}`}
      >
        <div
          className="absolute inset-y-0 left-0 w-1"
          style={{
            backgroundColor: content.accent,
          }}
        />

        <div className="p-5 sm:p-6 lg:p-7">
          <div className="flex flex-col gap-6 lg:flex-row lg:items-center lg:justify-between">

            {/* LEFT SIDE */}

            <div className="min-w-0 flex-1">

              <RiskBadge
                level={riskLevel}
                size="lg"
              />

              <div className="mt-5 flex items-start gap-3">

                <div
                  className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border"
                  style={{
                    backgroundColor: content.soft,
                    borderColor: content.border,
                    color: content.text,
                  }}
                >
                  {isHealthy ? (
                    <CheckCircle2 className="h-4 w-4" />
                  ) : (
                    <AlertTriangle className="h-4 w-4" />
                  )}
                </div>

                <div className="min-w-0">

                  <h3
                    className="text-lg font-semibold tracking-tight"
                    style={{
                      color: content.text,
                    }}
                  >
                    {content.title}
                  </h3>

                  <p className="mt-1.5 max-w-2xl text-sm leading-6 text-slate-600">
                    {content.description}
                  </p>

                </div>

              </div>

              <div className="mt-6 border-t border-slate-200/80 pt-4">

                <div className="flex flex-wrap items-center gap-x-6 gap-y-2">

                  <MetadataItem
                    label="Confidence"
                    value={confidence}
                  />

                  {filename && (
                    <MetadataItem
                      label="Capture"
                      value={filename}
                      mono
                    />
                  )}

                  {uploadedAt && (
                    <MetadataItem
                      label="Analyzed"
                      value={formatDate(uploadedAt)}
                    />
                  )}

                </div>

              </div>

            </div>

            {/* RISK SCORE */}

            <div className="flex shrink-0 justify-center">

              <div className="flex items-center gap-5 rounded-xl border border-slate-200 bg-white px-5 py-4 shadow-sm">

                <div className="relative h-[92px] w-[92px]">

                  <svg
                    className="h-[92px] w-[92px] -rotate-90"
                    viewBox="0 0 36 36"
                    aria-label={`Risk score ${score} out of 100`}
                  >
                    <path
                      stroke="#e2e8f0"
                      strokeWidth="3.2"
                      fill="none"
                      strokeLinecap="round"
                      d="
                        M18 2.5
                        a 15.5 15.5 0 1 1 0 31
                        a 15.5 15.5 0 1 1 0 -31
                      "
                    />

                    <path
                      stroke={content.accent}
                      strokeWidth="3.2"
                      fill="none"
                      strokeLinecap="round"
                      strokeDasharray={`${score}, 100`}
                      d="
                        M18 2.5
                        a 15.5 15.5 0 1 1 0 31
                        a 15.5 15.5 0 1 1 0 -31
                      "
                    />
                  </svg>

                  <div className="absolute inset-0 flex flex-col items-center justify-center">

                    <span
                      className="font-mono text-2xl font-semibold leading-none"
                      style={{
                        color: content.text,
                      }}
                    >
                      {score}
                    </span>

                    <span className="mt-1 font-mono text-[9px] text-slate-400">
                      / 100
                    </span>

                  </div>

                </div>

                <div className="w-[115px]">

                  <p className="text-xs font-semibold text-slate-900">
                    Risk score
                  </p>

                  <p className="mt-1.5 text-[10px] leading-4 text-slate-500">
                    Higher scores indicate greater observed security risk.
                  </p>

                </div>

              </div>

            </div>

          </div>
        </div>
      </section>


      {/* =====================================================
          KEY METRICS
      ====================================================== */}

      <section className="grid grid-cols-2 gap-3 lg:grid-cols-4">

        <MetricCard
          icon={Layers}
          label="Total sessions"
          value={totalSessions}
          iconClass="text-brand-600"
          iconBg="border-brand-100 bg-brand-50"
        />

        <MetricCard
          icon={AlertTriangle}
          label="Vulnerable sessions"
          value={summary?.vulnerable_sessions ?? 0}
          valueClass={
            summary?.vulnerable_sessions > 0
              ? 'text-red-700'
              : 'text-slate-900'
          }
          iconClass="text-red-600"
          iconBg="border-red-100 bg-red-50"
        />

        <MetricCard
          icon={Bug}
          label="Security findings"
          value={summary?.findings_count ?? 0}
          valueClass={
            summary?.findings_count > 0
              ? 'text-amber-700'
              : 'text-slate-900'
          }
          iconClass="text-amber-600"
          iconBg="border-amber-100 bg-amber-50"
        />

        <MetricCard
          icon={Unlock}
          label="Plaintext sessions"
          value={plaintext}
          valueClass={
            plaintext > 0
              ? 'text-rose-700'
              : 'text-slate-900'
          }
          iconClass="text-rose-600"
          iconBg="border-rose-100 bg-rose-50"
        />

      </section>


      {/* =====================================================
          PROTOCOL + TRANSPORT
      ====================================================== */}

      <section className="overflow-hidden rounded-2xl border border-slate-200 bg-white">

        <div className="grid grid-cols-1 lg:grid-cols-2">

          {/* =================================================
              PROTOCOL COVERAGE
          ================================================== */}

          <div className="p-5 sm:p-6">

            <div className="flex items-start justify-between gap-4">

              <div className="flex items-center gap-3">

                <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-brand-100 bg-brand-50">
                  <Network className="h-4 w-4 text-brand-600" />
                </div>

                <div>
                  <h3 className="text-sm font-semibold text-slate-900">
                    Protocol coverage
                  </h3>

                  <p className="mt-0.5 text-[11px] text-slate-500">
                    Email protocols detected in the capture
                  </p>
                </div>

              </div>

              <div className="rounded-md bg-slate-50 px-2.5 py-1.5 text-right">
                <p className="font-mono text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                  Sessions
                </p>

                <p className="mt-0.5 font-mono text-sm font-semibold text-slate-900">
                  {totalSessions}
                </p>
              </div>

            </div>


            <div className="mt-5 grid grid-cols-3 gap-2.5">

              <ProtocolCard
                label="SMTP"
                description="Mail transfer"
                value={smtp}
                tone="blue"
              />

              <ProtocolCard
                label="IMAP"
                description="Mailbox access"
                value={imap}
                tone="blueLight"
              />

              <ProtocolCard
                label="POP3"
                description="Mail retrieval"
                value={pop3}
                tone="neutral"
              />

            </div>

          </div>


          {/* =================================================
              TRANSPORT ENCRYPTION
          ================================================== */}

          <div className="border-t border-slate-100 p-5 sm:p-6 lg:border-l lg:border-t-0">

            <div className="flex items-start justify-between gap-4">

              <div className="flex items-center gap-3">

                <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-emerald-100 bg-emerald-50">
                  <LockKeyhole className="h-4 w-4 text-emerald-600" />
                </div>

                <div>
                  <h3 className="text-sm font-semibold text-slate-900">
                    Transport encryption
                  </h3>

                  <p className="mt-0.5 text-[11px] text-slate-500">
                    Encryption methods observed
                  </p>
                </div>

              </div>

              <div className="rounded-md bg-slate-50 px-2.5 py-1.5 text-right">
                <p className="font-mono text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                  Protection
                </p>

                <p className="mt-0.5 font-mono text-sm font-semibold text-slate-900">
                  {starttls + implicitTls + plaintext}
                </p>
              </div>

            </div>


            <div className="mt-5 grid grid-cols-1 gap-2.5 sm:grid-cols-3">

              <EncryptionCard
                label="STARTTLS"
                description="Explicit TLS"
                value={starttls}
                tone="blue"
              />

              <EncryptionCard
                label="Implicit TLS"
                description="TLS from start"
                value={implicitTls}
                tone="green"
              />

              <EncryptionCard
                label="Plaintext"
                description="Unencrypted"
                value={plaintext}
                tone={plaintext > 0 ? 'red' : 'neutral'}
              />

            </div>

          </div>

        </div>

      </section>

    </div>
  );
}


/* =============================================================
   METRIC CARD
============================================================= */

function MetricCard({
  icon: Icon,
  label,
  value,
  iconClass,
  iconBg,
  valueClass = 'text-slate-900',
}) {
  return (
    <div className="rounded-xl border border-slate-200 bg-white p-4 transition-all duration-200 hover:border-slate-300 hover:shadow-sm">

      <div className="flex items-center gap-3">

        <div
          className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border ${iconBg}`}
        >
          <Icon className={`h-4 w-4 ${iconClass}`} />
        </div>

        <div className="min-w-0">

          <p className="truncate text-[10px] font-medium uppercase tracking-wider text-slate-500">
            {label}
          </p>

          <p
            className={`mt-0.5 font-mono text-xl font-semibold leading-6 ${valueClass}`}
          >
            {value}
          </p>

        </div>

      </div>

    </div>
  );
}


/* =============================================================
   PROTOCOL CARD
============================================================= */

function ProtocolCard({
  label,
  description,
  value,
  tone,
}) {
  const styles = {
    blue: {
      wrapper:
        'border-sky-200 bg-sky-50/50',
      dot: 'bg-sky-500',
      label: 'text-slate-800',
      value: 'text-slate-900',
    },

    blueLight: {
      wrapper:
        'border-slate-200 bg-slate-50',
      dot: 'bg-sky-400',
      label: 'text-slate-800',
      value: 'text-slate-900',
    },

    neutral: {
      wrapper:
        'border-slate-200 bg-slate-50',
      dot: 'bg-slate-400',
      label: 'text-slate-800',
      value: 'text-slate-900',
    },
  };

  const style =
    styles[tone] || styles.neutral;

  return (
    <div
      className={`rounded-xl border p-3.5 ${style.wrapper}`}
    >

      <div className="flex items-center justify-between gap-2">

        <div className="flex items-center gap-2">

          <span
            className={`h-2 w-2 rounded-full ${style.dot}`}
          />

          <span
            className={`font-mono text-xs font-semibold ${style.label}`}
          >
            {label}
          </span>

        </div>

        <span
          className={`font-mono text-lg font-semibold leading-none ${style.value}`}
        >
          {value}
        </span>

      </div>

      <p className="mt-2 text-[10px] text-slate-500">
        {description}
      </p>

    </div>
  );
}


/* =============================================================
   ENCRYPTION CARD
============================================================= */

function EncryptionCard({
  label,
  description,
  value,
  tone,
}) {
  const styles = {
    blue: {
      wrapper:
        'border-sky-200 bg-sky-50/40',
      dot: 'bg-sky-500',
      label: 'text-sky-700',
      value: 'text-slate-900',
    },

    green: {
      wrapper:
        'border-emerald-200 bg-emerald-50/40',
      dot: 'bg-emerald-500',
      label: 'text-emerald-700',
      value: 'text-slate-900',
    },

    red: {
      wrapper:
        'border-red-200 bg-red-50/60',
      dot: 'bg-red-500',
      label: 'text-red-700',
      value: 'text-red-800',
    },

    neutral: {
      wrapper:
        'border-slate-200 bg-slate-50',
      dot: 'bg-slate-400',
      label: 'text-slate-600',
      value: 'text-slate-900',
    },
  };

  const style =
    styles[tone] || styles.neutral;

  return (
    <div
      className={`rounded-xl border p-3.5 ${style.wrapper}`}
    >

      <div className="flex items-center justify-between gap-2">

        <div className="flex min-w-0 items-center gap-2">

          <span
            className={`h-2 w-2 shrink-0 rounded-full ${style.dot}`}
          />

          <span
            className={`truncate text-xs font-semibold ${style.label}`}
          >
            {label}
          </span>

        </div>

        <span
          className={`font-mono text-lg font-semibold leading-none ${style.value}`}
        >
          {value}
        </span>

      </div>

      <p className="mt-2 text-[10px] text-slate-500">
        {description}
      </p>

    </div>
  );
}


/* =============================================================
   METADATA
============================================================= */

function MetadataItem({
  label,
  value,
  mono = false,
}) {
  return (
    <span className="flex min-w-0 items-center gap-1.5 text-[10px] text-slate-500">

      <span>{label}</span>

      <strong
        className={`max-w-[200px] truncate font-medium text-slate-700 ${
          mono ? 'font-mono' : ''
        }`}
        title={value}
      >
        {value}
      </strong>

    </span>
  );
}


/* =============================================================
   DATE
============================================================= */

function formatDate(value) {
  try {
    const date = new Date(value);

    if (Number.isNaN(date.getTime())) {
      return value;
    }

    return date.toLocaleString(undefined, {
      dateStyle: 'medium',
      timeStyle: 'short',
    });
  } catch {
    return value;
  }
}