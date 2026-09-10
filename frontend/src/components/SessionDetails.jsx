import React from 'react';
import { X, Shield, Lock, Key, Award, AlertCircle, FileText, CheckCircle2, XCircle, HelpCircle, EyeOff } from 'lucide-react';
import { formatTriState, formatEncryptionMode, formatDate } from '../utils/formatters';
import RiskBadge from './RiskBadge';

export default function SessionDetails({ session, onClose }) {
  if (!session) return null;

  const enc = formatEncryptionMode(session?.security?.encryption_mode);

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-in fade-in duration-150"
      role="dialog"
      aria-modal="true"
      aria-labelledby="session-modal-title"
    >
      <div className="relative w-full max-w-3xl rounded-2xl bg-slate-900 border border-slate-700 shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="p-5 border-b border-slate-800 flex items-center justify-between bg-slate-950/40">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-brand-500/10 border border-brand-500/30 flex items-center justify-center text-brand-400">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 id="session-modal-title" className="text-base font-bold text-white font-mono">
                  {session.session_id}
                </h3>
                <span className={`text-[11px] px-2 py-0.5 rounded-full border font-mono ${enc.badge}`}>
                  {enc.label}
                </span>
                <RiskBadge level={session.risk_label || 'LOW'} size="sm" />
              </div>
              <p className="text-xs text-slate-400">
                {session.protocol} ({session.service || 'email-service'}) • Stream Inspection
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
            aria-label="Close session details"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Scrollable Content */}
        <div className="p-6 overflow-y-auto space-y-6 text-xs">
          {/* Connection Endpoints */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 p-3.5 rounded-xl bg-slate-950/60 border border-slate-800 font-mono">
            <div>
              <span className="text-[10px] text-slate-500 uppercase tracking-wider block">Client (Source)</span>
              <span className="text-slate-200 text-sm font-semibold">
                {session.client_ip || '—'}:{session.client_port || '—'}
              </span>
            </div>
            <div>
              <span className="text-[10px] text-slate-500 uppercase tracking-wider block">Server (Destination)</span>
              <span className="text-slate-200 text-sm font-semibold">
                {session.server_ip || '—'}:{session.server_port || '—'}
              </span>
            </div>
          </div>

          {/* Security & Protocol Handshake (Tri-state evidence) */}
          <div className="space-y-2.5">
            <h4 className="text-xs font-semibold uppercase tracking-wider text-brand-400 flex items-center gap-2">
              <Lock className="w-4 h-4" />
              <span>Protocol Handshake & Upgrade Controls</span>
            </h4>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
              {/* Upgrade Advertised */}
              <div className="p-3 rounded-xl bg-slate-800/40 border border-slate-800 flex items-center justify-between">
                <div>
                  <span className="text-slate-300 font-medium block">Upgrade Advertised</span>
                  <span className="text-[10px] text-slate-500">STARTTLS / STLS capability announced</span>
                </div>
                {(() => {
                  const state = formatTriState(session.security?.upgrade_advertised);
                  return <span className={`px-2 py-0.5 rounded font-mono text-[11px] border ${state.badgeClass}`}>{state.text}</span>;
                })()}
              </div>

              {/* Upgrade Requested */}
              <div className="p-3 rounded-xl bg-slate-800/40 border border-slate-800 flex items-center justify-between">
                <div>
                  <span className="text-slate-300 font-medium block">Upgrade Requested</span>
                  <span className="text-[10px] text-slate-500">Client initiated TLS upgrade command</span>
                </div>
                {(() => {
                  const state = formatTriState(session.security?.upgrade_requested);
                  return <span className={`px-2 py-0.5 rounded font-mono text-[11px] border ${state.badgeClass}`}>{state.text}</span>;
                })()}
              </div>

              {/* Upgrade Succeeded */}
              <div className="p-3 rounded-xl bg-slate-800/40 border border-slate-800 flex items-center justify-between">
                <div>
                  <span className="text-slate-300 font-medium block">Upgrade Succeeded</span>
                  <span className="text-[10px] text-slate-500">TLS session established after upgrade</span>
                </div>
                {(() => {
                  const state = formatTriState(session.security?.upgrade_succeeded);
                  return <span className={`px-2 py-0.5 rounded font-mono text-[11px] border ${state.badgeClass}`}>{state.text}</span>;
                })()}
              </div>

              {/* Authentication Before TLS (Critical Check) */}
              <div className="p-3 rounded-xl bg-slate-800/40 border border-slate-800 flex items-center justify-between">
                <div>
                  <span className="text-slate-300 font-medium block">Auth Before TLS</span>
                  <span className="text-[10px] text-slate-500">AUTH commands sent over plaintext</span>
                </div>
                {(() => {
                  const state = formatTriState(session.security?.authentication_before_tls);
                  const isVuln = state.text === 'YES';
                  return (
                    <span className={`px-2 py-0.5 rounded font-mono text-[11px] border ${isVuln ? 'bg-red-500/20 text-red-300 border-red-500/40 font-bold' : state.badgeClass}`}>
                      {state.text}
                    </span>
                  );
                })()}
              </div>

              {/* Capture Completeness */}
              <div className="p-3 rounded-xl bg-slate-800/40 border border-slate-800 flex items-center justify-between sm:col-span-2">
                <div>
                  <span className="text-slate-300 font-medium block">Capture Completeness</span>
                  <span className="text-[10px] text-slate-500">Full TCP 3-way handshake and stream teardown captured</span>
                </div>
                <span className="px-2 py-0.5 rounded font-mono text-[11px] bg-slate-800 text-slate-300 border border-slate-700">
                  {session.security?.capture_completeness || 'UNKNOWN'}
                </span>
              </div>
            </div>
          </div>

          {/* TLS Parameters */}
          <div className="space-y-2.5">
            <h4 className="text-xs font-semibold uppercase tracking-wider text-sky-400 flex items-center gap-2">
              <Key className="w-4 h-4" />
              <span>TLS Cryptographic Parameters</span>
            </h4>
            {session.tls ? (
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5 p-3.5 rounded-xl bg-slate-800/30 border border-slate-800 font-mono">
                <div>
                  <span className="text-[10px] text-slate-500 uppercase tracking-wider block">TLS Version</span>
                  <span className="text-slate-200 font-semibold text-xs">{session.tls.version || 'UNKNOWN'}</span>
                </div>
                <div>
                  <span className="text-[10px] text-slate-500 uppercase tracking-wider block">Forward Secrecy (PFS)</span>
                  <span className={`text-xs font-semibold ${session.tls.pfs === 'YES' ? 'text-emerald-400' : 'text-slate-300'}`}>
                    {session.tls.pfs || 'UNKNOWN'}
                  </span>
                </div>
                <div className="sm:col-span-3 pt-1">
                  <span className="text-[10px] text-slate-500 uppercase tracking-wider block">Cipher Suite</span>
                  <span className="text-slate-300 text-xs break-all">{session.tls.cipher_suite || 'None / Not Negotiated'}</span>
                </div>
              </div>
            ) : (
              <div className="p-3 rounded-xl bg-slate-950/40 border border-slate-800 text-slate-400 italic">
                No TLS cryptographic parameters observed in this session.
              </div>
            )}
          </div>

          {/* Certificate Information */}
          <div className="space-y-2.5">
            <h4 className="text-xs font-semibold uppercase tracking-wider text-purple-400 flex items-center gap-2">
              <Award className="w-4 h-4" />
              <span>X.509 Certificate Chain</span>
            </h4>
            {session.certificate?.visibility === 'NOT_OBSERVABLE' ? (
              <div className="p-3.5 rounded-xl bg-purple-950/20 border border-purple-500/30 flex items-center gap-3 text-purple-300">
                <EyeOff className="w-5 h-5 text-purple-400 shrink-0" />
                <div>
                  <p className="font-semibold">Certificate Visibility: NOT OBSERVABLE</p>
                  <p className="text-[11px] text-purple-300/80 mt-0.5">
                    TLS 1.3 encrypted handshake or packet capture began after the Certificate payload was delivered.
                  </p>
                </div>
              </div>
            ) : session.certificate?.subject ? (
              <div className="p-3.5 rounded-xl bg-slate-800/30 border border-slate-800 space-y-2 font-mono">
                <div>
                  <span className="text-[10px] text-slate-500 uppercase tracking-wider block">Subject</span>
                  <span className="text-slate-200 text-xs break-all">{session.certificate.subject}</span>
                </div>
                <div>
                  <span className="text-[10px] text-slate-500 uppercase tracking-wider block">Issuer</span>
                  <span className="text-slate-300 text-xs break-all">{session.certificate.issuer || 'UNKNOWN'}</span>
                </div>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-1 text-[11px]">
                  <div>
                    <span className="text-[10px] text-slate-500 uppercase tracking-wider block">Valid From</span>
                    <span className="text-slate-300">{formatDate(session.certificate.valid_from)}</span>
                  </div>
                  <div>
                    <span className="text-[10px] text-slate-500 uppercase tracking-wider block">Valid Until</span>
                    <span className="text-slate-300">{formatDate(session.certificate.valid_until)}</span>
                  </div>
                  <div>
                    <span className="text-[10px] text-slate-500 uppercase tracking-wider block">Key Algorithm</span>
                    <span className="text-slate-300">{session.certificate.key_type || '—'} {session.certificate.key_size ? `(${session.certificate.key_size} bit)` : ''}</span>
                  </div>
                  <div>
                    <span className="text-[10px] text-slate-500 uppercase tracking-wider block">Self-Signed</span>
                    <span className={session.certificate.self_signed ? 'text-amber-400 font-semibold' : 'text-slate-300'}>
                      {session.certificate.self_signed === null ? 'UNKNOWN' : session.certificate.self_signed ? 'YES' : 'NO'}
                    </span>
                  </div>
                </div>
              </div>
            ) : (
              <div className="p-3 rounded-xl bg-slate-950/40 border border-slate-800 text-slate-400 italic">
                No certificate payload captured for this session.
              </div>
            )}
          </div>
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-slate-800 bg-slate-950/40 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium transition-colors"
          >
            Close Details
          </button>
        </div>
      </div>
    </div>
  );
}
