import React, { useMemo, useState } from 'react';
import {
  Layers,
  Search,
  Eye,
  ShieldCheck,
  ShieldAlert,
  SlidersHorizontal,
  X,
} from 'lucide-react';

import { formatEncryptionMode } from '../utils/formatters';
import SessionDetails from './SessionDetails';

export default function SessionTable({
  sessions = [],
  findings = [],
}) {
  const [selectedSession, setSelectedSession] = useState(null);
  const [protocolFilter, setProtocolFilter] = useState('ALL');
  const [encryptionFilter, setEncryptionFilter] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');

  /* =============================================================
     VULNERABLE SESSION MAP
  ============================================================= */

  const vulnerableSessionMap = useMemo(() => {
    const map = new Set();

    (findings || []).forEach((finding) => {
      if (
        finding.severity === 'CRITICAL' ||
        finding.severity === 'HIGH'
      ) {
        if (finding.session_id) {
          map.add(finding.session_id);
        }
      }
    });

    return map;
  }, [findings]);

  /* =============================================================
     FILTERED SESSIONS
  ============================================================= */

  const filteredSessions = useMemo(() => {
    const query = searchQuery.trim().toLowerCase();

    return (sessions || []).filter((session) => {
      const protocol = (
        session.protocol || ''
      ).toUpperCase();

      const encryption = (
        session.security?.encryption_mode || ''
      ).toUpperCase();

      const matchProtocol =
        protocolFilter === 'ALL' ||
        protocol === protocolFilter;

      const matchEncryption =
        encryptionFilter === 'ALL' ||
        encryption === encryptionFilter;

      const matchSearch =
        !query ||
        (session.session_id || '')
          .toLowerCase()
          .includes(query) ||
        (session.client_ip || '')
          .toLowerCase()
          .includes(query) ||
        (session.server_ip || '')
          .toLowerCase()
          .includes(query) ||
        (session.protocol || '')
          .toLowerCase()
          .includes(query) ||
        (session.service || '')
          .toLowerCase()
          .includes(query);

      return (
        matchProtocol &&
        matchEncryption &&
        matchSearch
      );
    });
  }, [
    sessions,
    protocolFilter,
    encryptionFilter,
    searchQuery,
  ]);

  const hasActiveFilters =
    protocolFilter !== 'ALL' ||
    encryptionFilter !== 'ALL' ||
    searchQuery.trim() !== '';

  const clearFilters = () => {
    setProtocolFilter('ALL');
    setEncryptionFilter('ALL');
    setSearchQuery('');
  };

  return (
    <section className="w-full">

      {/* =========================================================
          HEADER
      ========================================================== */}

      <div className="mb-4 flex flex-col gap-4 xl:flex-row xl:items-end xl:justify-between">

        <div className="min-w-0">

          <div className="flex flex-wrap items-center gap-2">

            <div className="flex items-center gap-2.5">

              <div className="flex h-8 w-8 items-center justify-center rounded-lg border border-brand-100 bg-brand-50">
                <Layers className="h-4 w-4 text-brand-600" />
              </div>

              <div>
                <h3 className="text-sm font-semibold text-slate-900">
                  Reconstructed sessions
                </h3>

                <p className="mt-0.5 text-[11px] text-slate-500">
                  Email connections reconstructed from the packet capture
                </p>
              </div>

            </div>

            <span className="rounded-md border border-slate-200 bg-white px-2 py-1 font-mono text-[10px] font-semibold text-slate-600">
              {filteredSessions.length}
              <span className="mx-1 text-slate-300">
                /
              </span>
              {sessions.length}
            </span>

          </div>

        </div>


        {/* =======================================================
            FILTERS
        ======================================================== */}

        <div className="flex flex-col gap-2 sm:flex-row">

          {/* SEARCH */}

          <div className="relative min-w-0 sm:w-56">

            <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-400" />

            <input
              type="text"
              placeholder="Search sessions..."
              value={searchQuery}
              onChange={(e) =>
                setSearchQuery(e.target.value)
              }
              className="ui-input pl-9 pr-3 text-xs"
              aria-label="Search sessions"
            />

          </div>


          {/* PROTOCOL */}

          <select
            value={protocolFilter}
            onChange={(e) =>
              setProtocolFilter(e.target.value)
            }
            className="ui-input min-w-[125px] text-xs"
            aria-label="Filter by protocol"
          >
            <option value="ALL">
              All protocols
            </option>

            <option value="SMTP">
              SMTP
            </option>

            <option value="IMAP">
              IMAP
            </option>

            <option value="POP3">
              POP3
            </option>
          </select>


          {/* ENCRYPTION */}

          <select
            value={encryptionFilter}
            onChange={(e) =>
              setEncryptionFilter(e.target.value)
            }
            className="ui-input min-w-[135px] text-xs"
            aria-label="Filter by encryption"
          >
            <option value="ALL">
              All encryption
            </option>

            <option value="STARTTLS">
              STARTTLS
            </option>

            <option value="IMPLICIT_TLS">
              Implicit TLS
            </option>

            <option value="PLAINTEXT">
              Plaintext
            </option>
          </select>


          {hasActiveFilters && (
            <button
              type="button"
              onClick={clearFilters}
              className="ui-button ui-button-secondary shrink-0 px-3"
              title="Clear filters"
            >
              <X className="h-3.5 w-3.5" />
              Clear
            </button>
          )}

        </div>

      </div>


      {/* =========================================================
          ACTIVE FILTER MESSAGE
      ========================================================== */}

      {hasActiveFilters && (
        <div className="mb-3 flex items-center gap-2 rounded-lg border border-slate-200 bg-white px-3 py-2">

          <SlidersHorizontal className="h-3 w-3 text-brand-600" />

          <span className="text-[11px] text-slate-500">
            Showing
          </span>

          <span className="font-mono text-[11px] font-semibold text-slate-800">
            {filteredSessions.length}
          </span>

          <span className="text-[11px] text-slate-500">
            of
          </span>

          <span className="font-mono text-[11px] font-semibold text-slate-800">
            {sessions.length}
          </span>

          <span className="text-[11px] text-slate-500">
            sessions
          </span>

        </div>
      )}


      {/* =========================================================
          TABLE
      ========================================================== */}

      <div className="overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm">

        <div className="overflow-x-auto">

          <table className="w-full min-w-[980px] text-left">

            <thead>

              <tr className="border-b border-slate-200 bg-slate-50/80">

                <TableHeader>
                  Session
                </TableHeader>

                <TableHeader>
                  Protocol
                </TableHeader>

                <TableHeader>
                  Connection
                </TableHeader>

                <TableHeader>
                  Encryption
                </TableHeader>

                <TableHeader>
                  TLS
                </TableHeader>

                <TableHeader>
                  PFS
                </TableHeader>

                <TableHeader>
                  Security posture
                </TableHeader>

                <TableHeader align="right">
                  Action
                </TableHeader>

              </tr>

            </thead>


            <tbody className="divide-y divide-slate-100">

              {filteredSessions.length > 0 ? (

                filteredSessions.map((session) => {

                  const encryption =
                    formatEncryptionMode(
                      session.security
                        ?.encryption_mode
                    );

                  const isVulnerable =
                    vulnerableSessionMap.has(
                      session.session_id
                    ) ||
                    session.security
                      ?.authentication_before_tls ===
                      'YES' ||
                    session.security
                      ?.encryption_mode ===
                      'PLAINTEXT';

                  return (
                    <SessionRow
                      key={session.session_id}
                      session={session}
                      encryption={encryption}
                      isVulnerable={isVulnerable}
                      onInspect={() =>
                        setSelectedSession(session)
                      }
                    />
                  );
                })

              ) : (

                <tr>

                  <td
                    colSpan="8"
                    className="px-6 py-14 text-center"
                  >

                    <div className="mx-auto flex max-w-xs flex-col items-center">

                      <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-slate-200 bg-slate-50">
                        <Search className="h-4 w-4 text-slate-400" />
                      </div>

                      <p className="mt-3 text-xs font-semibold text-slate-800">
                        No matching sessions
                      </p>

                      <p className="mt-1 text-[11px] leading-5 text-slate-500">
                        Try changing the search term or clearing the active filters.
                      </p>

                      {hasActiveFilters && (
                        <button
                          type="button"
                          onClick={clearFilters}
                          className="mt-3 text-[11px] font-semibold text-brand-600 hover:text-brand-700"
                        >
                          Clear filters
                        </button>
                      )}

                    </div>

                  </td>

                </tr>

              )}

            </tbody>

          </table>

        </div>


        {/* =======================================================
            TABLE FOOTER
        ======================================================== */}

        {filteredSessions.length > 0 && (
          <div className="flex items-center justify-between border-t border-slate-100 bg-slate-50/50 px-4 py-3">

            <span className="text-[10px] text-slate-400">
              Select a session to inspect reconstructed traffic details
            </span>

            <span className="font-mono text-[10px] font-medium text-slate-500">
              {filteredSessions.length}{' '}
              result
              {filteredSessions.length !== 1
                ? 's'
                : ''}
            </span>

          </div>
        )}

      </div>


      {/* =========================================================
          SESSION DETAILS
      ========================================================== */}

      {selectedSession && (
        <SessionDetails
          session={selectedSession}
          onClose={() =>
            setSelectedSession(null)
          }
        />
      )}

    </section>
  );
}


/* ===============================================================
   TABLE HEADER
=============================================================== */

function TableHeader({
  children,
  align = 'left',
}) {
  return (
    <th
      scope="col"
      className={`px-4 py-3 text-[10px] font-semibold uppercase tracking-[0.08em] text-slate-500 ${
        align === 'right'
          ? 'text-right'
          : 'text-left'
      }`}
    >
      {children}
    </th>
  );
}


/* ===============================================================
   SESSION ROW
=============================================================== */

function SessionRow({
  session,
  encryption,
  isVulnerable,
  onInspect,
}) {
  return (
    <tr
      onClick={onInspect}
      className="group cursor-pointer transition-colors hover:bg-slate-50"
    >

      {/* SESSION */}

      <td className="px-4 py-4">

        <div className="flex items-center gap-3">

          <span
            className={`h-2 w-2 shrink-0 rounded-full ${
              isVulnerable
                ? 'bg-red-500'
                : 'bg-yellow-500'
            }`}
          />

          <div className="min-w-0">

            <p
              className="max-w-[180px] truncate font-mono text-xs font-semibold text-slate-800"
              title={session.session_id}
            >
              {session.session_id || '—'}
            </p>

            <p className="mt-0.5 text-[10px] text-slate-400">
              Click to inspect
            </p>

          </div>

        </div>

      </td>


      {/* PROTOCOL */}

      <td className="px-4 py-4">

        <div>

          <span className="inline-flex rounded-md border border-slate-200 bg-slate-50 px-2 py-1 font-mono text-[10px] font-semibold text-slate-700">
            {session.protocol || '—'}
          </span>

          {session.service && (
            <p className="mt-1.5 text-[10px] text-slate-400">
              {session.service}
            </p>
          )}

        </div>

      </td>


      {/* CONNECTION */}

      <td className="px-4 py-4">

        <div className="space-y-1.5">

          <Endpoint
            label="C"
            ip={session.client_ip}
            port={session.client_port}
          />

          <Endpoint
            label="S"
            ip={session.server_ip}
            port={session.server_port}
          />

        </div>

      </td>


      {/* ENCRYPTION */}

      <td className="px-4 py-4">

        <EncryptionBadge
          encryption={encryption}
        />

      </td>


      {/* TLS */}

      <td className="px-4 py-4">

        {session.tls?.version ? (

          <span className="font-mono text-[11px] font-semibold text-slate-700">
            {session.tls.version}
          </span>

        ) : (

          <span className="text-xs text-slate-300">
            —
          </span>

        )}

      </td>


      {/* PFS */}

      <td className="px-4 py-4">

        {session.tls?.pfs === 'YES' ? (

          <span className="inline-flex items-center gap-1.5 text-[10px] font-semibold text-yellow-700">

            <span className="h-1.5 w-1.5 rounded-full bg-yellow-500" />

            Yes

          </span>

        ) : session.tls?.pfs ? (

          <span className="text-[10px] font-medium text-slate-500">
            {session.tls.pfs}
          </span>

        ) : (

          <span className="text-xs text-slate-300">
            —
          </span>

        )}

      </td>


      {/* POSTURE */}

      <td className="px-4 py-4">

        {isVulnerable ? (

          <span className="inline-flex items-center gap-2 rounded-lg border border-red-200 bg-red-50 px-2.5 py-1.5">

            <ShieldAlert className="h-3.5 w-3.5 text-red-600" />

            <span className="text-[10px] font-semibold text-red-700">
              Vulnerable
            </span>

          </span>

        ) : (

          <span className="inline-flex items-center gap-2 rounded-lg border border-yellow-200 bg-yellow-50 px-2.5 py-1.5">

            <ShieldCheck className="h-3.5 w-3.5 text-yellow-600" />

            <span className="text-[10px] font-semibold text-yellow-700">
              Protected
            </span>

          </span>

        )}

      </td>


      {/* ACTION */}

      <td className="px-4 py-4 text-right">

        <button
          type="button"
          onClick={(event) => {
            event.stopPropagation();
            onInspect();
          }}
          className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-[10px] font-semibold text-slate-600 shadow-sm transition-all hover:border-brand-200 hover:bg-brand-50 hover:text-brand-700 focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-500/20"
          aria-label={`Inspect session ${session.session_id}`}
        >
          <Eye className="h-3.5 w-3.5 text-brand-600" />
          Inspect
        </button>

      </td>

    </tr>
  );
}


/* ===============================================================
   ENCRYPTION BADGE
=============================================================== */

function EncryptionBadge({
  encryption,
}) {
  const label = encryption?.label || 'Unknown';

  const normalized = label
    .toUpperCase()
    .replace(/\s+/g, '_');

  let classes =
    'border-slate-200 bg-slate-50 text-slate-600';

  if (
    normalized.includes('PLAINTEXT')
  ) {
    classes =
      'border-red-200 bg-red-50 text-red-700';
  } else if (
    normalized.includes('STARTTLS')
  ) {
    classes =
      'border-sky-200 bg-sky-50 text-sky-700';
  } else if (
    normalized.includes('TLS')
  ) {
    classes =
      'border-yellow-200 bg-yellow-50 text-yellow-700';
  }

  return (
    <span
      className={`inline-flex rounded-lg border px-2.5 py-1.5 text-[10px] font-semibold ${classes}`}
    >
      {label}
    </span>
  );
}


/* ===============================================================
   ENDPOINT
=============================================================== */

function Endpoint({
  label,
  ip,
  port,
}) {
  return (
    <div className="flex items-center gap-2">

      <span className="flex h-4 w-4 shrink-0 items-center justify-center rounded bg-slate-100 font-mono text-[8px] font-semibold text-slate-500">
        {label}
      </span>

      <span
        className="font-mono text-[10px] text-slate-600"
        title={ip}
      >
        {ip || '—'}
      </span>

      {port && (
        <span className="font-mono text-[10px] text-slate-400">
          :{port}
        </span>
      )}

    </div>
  );
}