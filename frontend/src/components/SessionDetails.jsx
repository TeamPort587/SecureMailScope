import React from 'react';
import {
  X,
  Shield,
  Lock,
  Key,
  Award,
  EyeOff,
  CheckCircle2,
  XCircle,
  HelpCircle,
} from 'lucide-react';

import {
  formatTriState,
  formatEncryptionMode,
  formatDate,
} from '../utils/formatters';

export default function SessionDetails({ session, onClose }) {
  if (!session) return null;

  const enc = formatEncryptionMode(
    session?.security?.encryption_mode
  );

  const TriStateBadge = ({ value, vulnerable = false }) => {
    const state = formatTriState(value);

    const isYes = state.text === 'YES';
    const isNo = state.text === 'NO';

    let styles =
      'border-slate-200 bg-slate-50 text-slate-600';

    if (vulnerable && isYes) {
      styles =
        'border-red-200 bg-red-50 text-red-700';
    } else if (isYes) {
      styles =
        'border-yellow-200 bg-yellow-50 text-yellow-700';
    } else if (isNo) {
      styles =
        'border-slate-200 bg-slate-100 text-slate-500';
    } else {
      styles =
        'border-amber-200 bg-amber-50 text-amber-700';
    }

    return (
      <span
        className={`
          inline-flex items-center rounded-lg border
          px-2.5 py-1 text-[11px] font-semibold
          font-mono tracking-wide
          ${styles}
        `}
      >
        {state.text}
      </span>
    );
  };

  const SectionHeader = ({
    icon: Icon,
    title,
    description,
    color = 'brand',
  }) => {
    const colorStyles = {
      brand:
        'bg-brand-500/10 border-brand-500/20 text-brand-600',
      sky:
        'bg-sky-50 border-sky-200 text-sky-600',
      purple:
        'bg-violet-50 border-violet-200 text-violet-600',
    };

    return (
      <div className="flex items-center gap-3">
        <div
          className={`
            flex h-9 w-9 shrink-0 items-center justify-center
            rounded-xl border
            ${colorStyles[color]}
          `}
        >
          <Icon className="h-4 w-4" />
        </div>

        <div>
          <h4 className="text-sm font-semibold text-slate-800">
            {title}
          </h4>

          {description && (
            <p className="mt-0.5 text-[11px] text-slate-500">
              {description}
            </p>
          )}
        </div>
      </div>
    );
  };

  const ControlCard = ({
    title,
    description,
    value,
    vulnerable = false,
  }) => {
    return (
      <div
        className="
          rounded-xl
          border border-slate-200/90
          bg-white
          px-4 py-3.5
          shadow-[0_1px_2px_rgba(15,23,42,0.025)]
          transition-colors
          hover:border-slate-300
        "
      >
        <div className="flex items-center justify-between gap-4">
          <div className="min-w-0">
            <p className="text-sm font-semibold text-slate-700">
              {title}
            </p>

            <p className="mt-1 text-[11px] leading-5 text-slate-500">
              {description}
            </p>
          </div>

          <div className="shrink-0">
            <TriStateBadge
              value={value}
              vulnerable={vulnerable}
            />
          </div>
        </div>
      </div>
    );
  };

  return (
    <div
      className="
        fixed inset-0 z-50
        flex items-center justify-center
        bg-slate-900/25
        p-4
        backdrop-blur-sm
        animate-in fade-in duration-150
      "
      role="dialog"
      aria-modal="true"
      aria-labelledby="session-modal-title"
    >
      <div
        className="
          relative flex w-full max-w-4xl flex-col
          overflow-hidden rounded-2xl
          border border-slate-200
          bg-[#f8fafc]
          shadow-[0_24px_80px_rgba(15,23,42,0.18)]
          max-h-[90vh]
        "
      >
        {/* HEADER */}

        <div
          className="
            flex items-center justify-between
            border-b border-slate-200
            bg-gradient-to-r
            from-brand-500/[0.035]
            via-white
            to-white
            px-6 py-5
          "
        >
          <div className="flex items-center gap-3.5">
            <div
              className="
                flex h-11 w-11 items-center justify-center
                rounded-xl
                border border-brand-500/20
                bg-brand-500/[0.07]
              "
            >
              <Shield className="h-5 w-5 text-brand-600" />
            </div>

            <div>
              <div className="flex flex-wrap items-center gap-2.5">
                <h3
                  id="session-modal-title"
                  className="
                    font-mono text-base
                    font-bold text-slate-800
                  "
                >
                  {session.session_id}
                </h3>

                <span
                  className="
    inline-flex items-center
    rounded-lg border
    border-brand-500/25
    bg-brand-500/10
    px-3 py-1.5
    text-[10px]
    font-semibold
    uppercase
    tracking-wide
    text-brand-600
  "
                >
                  {enc.label}
                </span>
              </div>

              <p className="mt-1 text-xs text-slate-500">
                {session.protocol}
                {' · '}
                {session.service || 'email-service'}
                {' · '}
                Session security inspection
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="
              flex h-9 w-9 items-center justify-center
              rounded-xl
              border border-transparent
              text-slate-400
              transition-all
              hover:border-slate-200
              hover:bg-slate-100
              hover:text-slate-700
            "
            aria-label="Close session details"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* CONTENT */}

        <div
          className="
            flex-1 overflow-y-auto
            px-6 py-6
            space-y-8
          "
        >
          {/* CONNECTION */}

          <section className="space-y-3">
            <SectionHeader
              icon={Shield}
              title="Connection Endpoints"
              description="Network participants reconstructed from the captured stream"
              color="brand"
            />

            <div
              className="
                grid grid-cols-1 gap-3
                sm:grid-cols-2
              "
            >
              {/* CLIENT */}

              <div
                className="
                  rounded-xl
                  border border-slate-200
                  bg-gradient-to-br
                  from-brand-500/[0.045]
                  to-white
                  p-4
                "
              >
                <p
                  className="
                    text-[10px]
                    font-semibold uppercase
                    tracking-wider text-slate-400
                  "
                >
                  Client · Source
                </p>

                <p
                  className="
                    mt-2
                    font-mono text-sm
                    font-semibold text-slate-700
                  "
                >
                  {session.client_ip || '—'}
                  <span className="mx-1 text-slate-400">
                    :
                  </span>
                  {session.client_port || '—'}
                </p>
              </div>

              {/* SERVER */}

              <div
                className="
                  rounded-xl
                  border border-slate-200
                  bg-gradient-to-br
                  from-sky-500/[0.04]
                  to-white
                  p-4
                "
              >
                <p
                  className="
                    text-[10px]
                    font-semibold uppercase
                    tracking-wider text-slate-400
                  "
                >
                  Server · Destination
                </p>

                <p
                  className="
                    mt-2
                    font-mono text-sm
                    font-semibold text-slate-700
                  "
                >
                  {session.server_ip || '—'}
                  <span className="mx-1 text-slate-400">
                    :
                  </span>
                  {session.server_port || '—'}
                </p>
              </div>
            </div>
          </section>

          {/* HANDSHAKE */}

          <section className="space-y-3">
            <SectionHeader
              icon={Lock}
              title="Protocol Handshake"
              description="TLS upgrade and authentication security controls"
              color="brand"
            />

            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <ControlCard
                title="Upgrade Advertised"
                description="STARTTLS or STLS capability was announced"
                value={
                  session.security?.upgrade_advertised
                }
              />

              <ControlCard
                title="Upgrade Requested"
                description="Client initiated a TLS upgrade command"
                value={
                  session.security?.upgrade_requested
                }
              />

              <ControlCard
                title="Upgrade Succeeded"
                description="TLS session was established after upgrade"
                value={
                  session.security?.upgrade_succeeded
                }
              />

              <ControlCard
                title="Authentication Before TLS"
                description="Authentication commands observed over plaintext"
                value={
                  session.security
                    ?.authentication_before_tls
                }
                vulnerable
              />

              {/* CAPTURE */}

              <div
                className="
                  sm:col-span-2
                  rounded-xl
                  border border-slate-200
                  bg-white
                  px-4 py-3.5
                  shadow-[0_1px_2px_rgba(15,23,42,0.025)]
                "
              >
                <div className="flex items-center justify-between gap-4">
                  <div>
                    <p className="text-sm font-semibold text-slate-700">
                      Capture Completeness
                    </p>

                    <p className="mt-1 text-[11px] text-slate-500">
                      TCP handshake and stream teardown
                      availability
                    </p>
                  </div>

                  <span
                    className="
                      shrink-0 rounded-lg
                      border border-slate-200
                      bg-slate-50
                      px-2.5 py-1
                      font-mono text-[11px]
                      font-semibold text-slate-600
                    "
                  >
                    {session.security
                      ?.capture_completeness || 'UNKNOWN'}
                  </span>
                </div>
              </div>
            </div>
          </section>

          {/* TLS */}

          <section className="space-y-3">
            <SectionHeader
              icon={Key}
              title="TLS Parameters"
              description="Negotiated cryptographic configuration"
              color="sky"
            />

            {session.tls ? (
              <div
                className="
                  rounded-xl
                  border border-slate-200
                  bg-gradient-to-br
                  from-sky-500/[0.035]
                  via-white
                  to-white
                  p-4
                "
              >
                <div
                  className="
                    grid grid-cols-1 gap-5
                    sm:grid-cols-3
                  "
                >
                  <div>
                    <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-400">
                      TLS Version
                    </p>

                    <p className="mt-1.5 font-mono text-sm font-semibold text-slate-700">
                      {session.tls.version || 'UNKNOWN'}
                    </p>
                  </div>

                  <div>
                    <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-400">
                      Forward Secrecy
                    </p>

                    <div className="mt-1.5 flex items-center gap-1.5">
                      {session.tls.pfs === 'YES' ? (
                        <CheckCircle2 className="h-3.5 w-3.5 text-yellow-500" />
                      ) : (
                        <HelpCircle className="h-3.5 w-3.5 text-slate-400" />
                      )}

                      <p
                        className={`
                          font-mono text-sm font-semibold
                          ${session.tls.pfs === 'YES'
                            ? 'text-yellow-600'
                            : 'text-slate-600'
                          }
                        `}
                      >
                        {session.tls.pfs || 'UNKNOWN'}
                      </p>
                    </div>
                  </div>

                  <div className="sm:col-span-3">
                    <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-400">
                      Cipher Suite
                    </p>

                    <p
                      className="
                        mt-1.5
                        break-all font-mono
                        text-xs leading-6 text-slate-600
                      "
                    >
                      {session.tls.cipher_suite ||
                        'None / Not Negotiated'}
                    </p>
                  </div>
                </div>
              </div>
            ) : (
              <div
                className="
                  rounded-xl
                  border border-dashed border-slate-200
                  bg-white/60
                  px-4 py-5
                  text-sm text-slate-500
                "
              >
                No TLS cryptographic parameters were
                observed in this session.
              </div>
            )}
          </section>

          {/* CERTIFICATE */}

          <section className="space-y-3">
            <SectionHeader
              icon={Award}
              title="Certificate Information"
              description="Observed X.509 certificate details"
              color="purple"
            />

            {session.certificate?.visibility ===
              'NOT_OBSERVABLE' ? (
              <div
                className="
                  flex items-start gap-3
                  rounded-xl
                  border border-violet-200
                  bg-gradient-to-r
                  from-violet-50
                  to-white
                  p-4
                "
              >
                <div
                  className="
                    flex h-9 w-9 shrink-0
                    items-center justify-center
                    rounded-lg
                    border border-violet-200
                    bg-white
                  "
                >
                  <EyeOff className="h-4 w-4 text-violet-600" />
                </div>

                <div>
                  <p className="text-sm font-semibold text-violet-800">
                    Certificate Not Observable
                  </p>

                  <p className="mt-1 text-[11px] leading-5 text-violet-600/80">
                    The certificate payload could not be
                    inspected because the TLS handshake was
                    encrypted or the capture began after
                    certificate delivery.
                  </p>
                </div>
              </div>
            ) : session.certificate?.subject ? (
              <div
                className="
                  rounded-xl
                  border border-slate-200
                  bg-white
                  p-4
                "
              >
                <div className="space-y-4">
                  <div>
                    <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-400">
                      Subject
                    </p>

                    <p className="mt-1.5 break-all font-mono text-xs leading-5 text-slate-700">
                      {session.certificate.subject}
                    </p>
                  </div>

                  <div>
                    <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-400">
                      Issuer
                    </p>

                    <p className="mt-1.5 break-all font-mono text-xs leading-5 text-slate-600">
                      {session.certificate.issuer ||
                        'UNKNOWN'}
                    </p>
                  </div>

                  <div
                    className="
                      grid grid-cols-2 gap-4
                      border-t border-slate-100
                      pt-4
                      sm:grid-cols-4
                    "
                  >
                    <div>
                      <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-400">
                        Valid From
                      </p>

                      <p className="mt-1 text-xs font-medium text-slate-600">
                        {formatDate(
                          session.certificate.valid_from
                        )}
                      </p>
                    </div>

                    <div>
                      <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-400">
                        Valid Until
                      </p>

                      <p className="mt-1 text-xs font-medium text-slate-600">
                        {formatDate(
                          session.certificate.valid_until
                        )}
                      </p>
                    </div>

                    <div>
                      <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-400">
                        Key Algorithm
                      </p>

                      <p className="mt-1 text-xs font-medium text-slate-600">
                        {session.certificate.key_type || '—'}

                        {session.certificate.key_size
                          ? ` (${session.certificate.key_size} bit)`
                          : ''}
                      </p>
                    </div>

                    <div>
                      <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-400">
                        Self-Signed
                      </p>

                      <p
                        className={`
                          mt-1 text-xs font-semibold
                          ${session.certificate.self_signed
                            ? 'text-amber-600'
                            : 'text-slate-600'
                          }
                        `}
                      >
                        {session.certificate.self_signed === null
                          ? 'UNKNOWN'
                          : session.certificate.self_signed
                            ? 'YES'
                            : 'NO'}
                      </p>
                    </div>
                  </div>
                </div>
              </div>
            ) : (
              <div
                className="
                  rounded-xl
                  border border-dashed border-slate-200
                  bg-white/60
                  px-4 py-5
                  text-sm text-slate-500
                "
              >
                No certificate payload was captured for this
                session.
              </div>
            )}
          </section>
        </div>

        {/* FOOTER */}

        <div
          className="
            flex justify-end
            border-t border-slate-200
            bg-white
            px-6 py-4
          "
        >
          <button
            onClick={onClose}
            className="
              rounded-xl
              border border-slate-200
              bg-white
              px-4 py-2
              text-xs font-semibold text-slate-600
              transition-all
              hover:border-slate-300
              hover:bg-slate-50
              hover:text-slate-800
            "
          >
            Close Details
          </button>
        </div>
      </div>
    </div>
  );
}