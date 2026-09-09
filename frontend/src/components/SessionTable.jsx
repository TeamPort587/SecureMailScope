import React, { useState, useMemo } from 'react';
import { Layers, Shield, Search, Eye, Filter, ArrowUpDown } from 'lucide-react';
import { formatEncryptionMode } from '../utils/formatters';
import SessionDetails from './SessionDetails';

export default function SessionTable({ sessions = [], findings = [] }) {
  const [selectedSession, setSelectedSession] = useState(null);
  const [protocolFilter, setProtocolFilter] = useState('ALL');
  const [encryptionFilter, setEncryptionFilter] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');

  // Map session IDs that have critical or high findings
  const vulnerableSessionMap = useMemo(() => {
    const map = new Set();
    (findings || []).forEach((f) => {
      if (f.severity === 'CRITICAL' || f.severity === 'HIGH') {
        map.add(f.session_id);
      }
    });
    return map;
  }, [findings]);

  // Filtered session list
  const filteredSessions = useMemo(() => {
    return (sessions || []).filter((s) => {
      const matchProto = protocolFilter === 'ALL' || (s.protocol || '').toUpperCase() === protocolFilter;
      const matchEnc = encryptionFilter === 'ALL' || (s.security?.encryption_mode || '').toUpperCase() === encryptionFilter;
      const q = searchQuery.toLowerCase();
      const matchQuery =
        !q ||
        (s.session_id || '').toLowerCase().includes(q) ||
        (s.client_ip || '').toLowerCase().includes(q) ||
        (s.server_ip || '').toLowerCase().includes(q) ||
        (s.protocol || '').toLowerCase().includes(q) ||
        (s.service || '').toLowerCase().includes(q);

      return matchProto && matchEnc && matchQuery;
    });
  }, [sessions, protocolFilter, encryptionFilter, searchQuery]);

  return (
    <div className="w-full space-y-3">
      {/* Header & Filter Controls */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h3 className="text-base font-bold text-white flex items-center gap-2">
            <Layers className="w-4 h-4 text-brand-400" />
            <span>Reconstructed Email Sessions</span>
            <span className="text-xs font-mono text-slate-400 px-2 py-0.5 rounded-full bg-slate-800 border border-slate-700">
              {filteredSessions.length} of {sessions.length}
            </span>
          </h3>
          <p className="text-xs text-slate-400">
            A single PCAP contains multiple distinct email connection streams.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {/* Search Box */}
          <div className="relative">
            <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500" />
            <input
              type="text"
              placeholder="Search IP, ID, port..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-8 pr-3 py-1.5 text-xs rounded-lg bg-slate-900 border border-slate-700 text-slate-200 placeholder-slate-500 focus:outline-none focus:border-brand-400 w-44"
            />
          </div>

          {/* Protocol Selector */}
          <select
            value={protocolFilter}
            onChange={(e) => setProtocolFilter(e.target.value)}
            className="px-2.5 py-1.5 text-xs rounded-lg bg-slate-900 border border-slate-700 text-slate-300 focus:outline-none focus:border-brand-400"
            aria-label="Filter by Protocol"
          >
            <option value="ALL">All Protocols</option>
            <option value="SMTP">SMTP</option>
            <option value="IMAP">IMAP</option>
            <option value="POP3">POP3</option>
          </select>

          {/* Encryption Selector */}
          <select
            value={encryptionFilter}
            onChange={(e) => setEncryptionFilter(e.target.value)}
            className="px-2.5 py-1.5 text-xs rounded-lg bg-slate-900 border border-slate-700 text-slate-300 focus:outline-none focus:border-brand-400"
            aria-label="Filter by Encryption Mode"
          >
            <option value="ALL">All Encryption</option>
            <option value="STARTTLS">STARTTLS</option>
            <option value="IMPLICIT_TLS">IMPLICIT TLS</option>
            <option value="PLAINTEXT">PLAINTEXT</option>
          </select>
        </div>
      </div>

      {/* Table Container */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 overflow-hidden shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-slate-300">
            <thead className="bg-slate-950/70 border-b border-slate-800 text-[11px] font-semibold text-slate-400 uppercase tracking-wider font-mono">
              <tr>
                <th scope="col" className="py-3 px-3.5">Session ID</th>
                <th scope="col" className="py-3 px-3">Proto / Service</th>
                <th scope="col" className="py-3 px-3">Client Endpoint</th>
                <th scope="col" className="py-3 px-3">Server Endpoint</th>
                <th scope="col" className="py-3 px-3">Encryption</th>
                <th scope="col" className="py-3 px-3">TLS Version</th>
                <th scope="col" className="py-3 px-3">PFS</th>
                <th scope="col" className="py-3 px-3">Security Posture</th>
                <th scope="col" className="py-3 px-3.5 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {filteredSessions.length > 0 ? (
                filteredSessions.map((session) => {
                  const enc = formatEncryptionMode(session.security?.encryption_mode);
                  const isVulnerable =
                    vulnerableSessionMap.has(session.session_id) ||
                    session.security?.authentication_before_tls === 'YES' ||
                    session.security?.encryption_mode === 'PLAINTEXT';

                  return (
                    <tr
                      key={session.session_id}
                      className="hover:bg-slate-800/40 transition-colors group cursor-pointer"
                      onClick={() => setSelectedSession(session)}
                    >
                      {/* Session ID */}
                      <td className="py-3 px-3.5 font-bold text-slate-200">
                        {session.session_id}
                      </td>

                      {/* Protocol & Service */}
                      <td className="py-3 px-3 font-sans">
                        <span className="font-semibold text-slate-100">{session.protocol}</span>
                        {session.service && (
                          <span className="text-[10px] text-slate-500 block">{session.service}</span>
                        )}
                      </td>

                      {/* Client IP & Port */}
                      <td className="py-3 px-3 text-slate-300">
                        {session.client_ip || '—'}
                        <span className="text-slate-500 text-[10px]">:{session.client_port || '—'}</span>
                      </td>

                      {/* Server IP & Port */}
                      <td className="py-3 px-3 text-slate-300">
                        {session.server_ip || '—'}
                        <span className="text-slate-500 text-[10px]">:{session.server_port || '—'}</span>
                      </td>

                      {/* Encryption Mode */}
                      <td className="py-3 px-3">
                        <span className={`px-2 py-0.5 rounded text-[10px] border ${enc.badge}`}>
                          {enc.label}
                        </span>
                      </td>

                      {/* TLS Version */}
                      <td className="py-3 px-3 text-slate-300">
                        {session.tls?.version || <span className="text-slate-600">—</span>}
                      </td>

                      {/* PFS */}
                      <td className="py-3 px-3">
                        {session.tls?.pfs === 'YES' ? (
                          <span className="text-emerald-400 font-semibold">YES</span>
                        ) : session.tls?.pfs ? (
                          <span className="text-slate-400">{session.tls.pfs}</span>
                        ) : (
                          <span className="text-slate-600">—</span>
                        )}
                      </td>

                      {/* Security Posture Status */}
                      <td className="py-3 px-3 font-sans">
                        {isVulnerable ? (
                          <span className="inline-flex items-center gap-1 text-[11px] font-semibold text-red-400">
                            <span className="w-1.5 h-1.5 rounded-full bg-red-500 animate-pulse" />
                            <span>Vulnerable</span>
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 text-[11px] font-medium text-emerald-400">
                            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
                            <span>Protected</span>
                          </span>
                        )}
                      </td>

                      {/* Action */}
                      <td className="py-3 px-3.5 text-right">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            setSelectedSession(session);
                          }}
                          className="inline-flex items-center gap-1 px-2.5 py-1 text-xs rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white transition-colors"
                          aria-label={`Inspect session ${session.session_id}`}
                        >
                          <Eye className="w-3.5 h-3.5 text-brand-400" />
                          <span>Inspect</span>
                        </button>
                      </td>
                    </tr>
                  );
                })
              ) : (
                <tr>
                  <td colSpan="9" className="py-8 text-center text-slate-500 font-sans">
                    No sessions match the current filter criteria.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Session Details Modal */}
      {selectedSession && (
        <SessionDetails
          session={selectedSession}
          onClose={() => setSelectedSession(null)}
        />
      )}
    </div>
  );
}
