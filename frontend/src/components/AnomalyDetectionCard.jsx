import React, { useState, useEffect, useMemo } from 'react';
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  HelpCircle,
  Info,
  ChevronDown,
  ChevronUp,
  ChevronRight,
  ChevronLeft,
  Cpu,
  Layers,
  ShieldAlert,
  Sliders,
  ExternalLink,
  Search,
  X,
  ArrowUp,
  ArrowDown,
  ArrowUpDown,
  Loader2,
  RotateCcw,
} from 'lucide-react';
import { analysisApi } from '../api/analysisApi';

const PAGE_SIZE = 15;

/**
 * Friendly names for all 30 Isolation Forest features so users see plain English.
 */
const FRIENDLY_FEATURE_NAMES = {
  // Protocol & Connection
  if_protocol_smtp: 'SMTP Protocol (Port 25/587)',
  if_protocol_imap: 'IMAP Protocol (Port 143/993)',
  if_protocol_pop3: 'POP3 Protocol (Port 110/995)',
  if_encryption_plaintext: 'Plaintext Communication',
  if_encryption_starttls: 'STARTTLS Protocol Mode',
  if_encryption_implicit: 'Implicit TLS Protocol Mode',
  if_upgrade_advertised: 'STARTTLS Advertised',
  if_upgrade_requested: 'STARTTLS Upgrade Requested',
  if_upgrade_succeeded: 'STARTTLS Upgrade Success',
  if_auth_before_tls: 'Authentication Before TLS',

  // TLS & Cryptography
  if_tls_version_numeric: 'TLS Protocol Version',
  if_cipher_strength: 'Cipher Suite Strength',
  if_pfs_present: 'Forward Secrecy (PFS)',
  if_tls_handshake_incomplete: 'TLS Handshake Completion',

  // Certificate Characteristics
  if_cert_visible: 'Certificate Visibility',
  if_cert_key_size: 'Certificate Key Size',
  if_cert_self_signed: 'Self-Signed Certificate',
  if_cert_validity_days: 'Certificate Expiration Days',
  if_cert_key_algo_rsa: 'Certificate Key: RSA',
  if_cert_key_algo_ec: 'Certificate Key: ECDSA',

  // TCP & Traffic Flow Telemetry
  if_packet_count: 'Total Packet Count',
  if_session_duration: 'Session Duration',
  if_client_packet_count: 'Client Packet Count',
  if_server_packet_count: 'Server Packet Count',
  if_packet_ratio: 'Client/Total Packet Ratio',
  if_tcp_reset_count: 'TCP Reset (RST) Count',
  if_session_complete: 'Session Completeness',

  // Security Finding Counts
  if_finding_count: 'Security Findings Count',
  if_high_sev_count: 'High/Critical Findings Count',
  if_medium_sev_count: 'Medium Findings Count',
};

/**
 * Uniformly formats raw numeric values into human-friendly, plain English phrases
 * across all 30 Isolation Forest features for both "This Session" and "Normal Benchmark".
 */
function formatFriendlyValue(feature, val, isBaseline = false) {
  if (val === null || val === undefined) return isBaseline ? 'Normal Baseline' : 'Standard';
  const num = typeof val === 'number' ? val : parseFloat(val);
  if (isNaN(num)) return String(val);

  const rawKey = String(feature || '').toLowerCase().trim();
  const key = rawKey.startsWith('if_') ? rawKey : `if_${rawKey}`;

  // 1. Authentication Before TLS
  if (key === 'if_auth_before_tls') {
    if (isBaseline) return 'Rare / Never (< 2%)';
    return num >= 0.5 ? 'YES (Cleartext Auth)' : 'No (Encrypted Auth)';
  }

  // 2. STARTTLS Handshake & Upgrades
  if (key === 'if_upgrade_succeeded') {
    if (isBaseline) return 'Standard (95%)';
    return num >= 0.5 ? 'YES (Completed)' : 'NO (Failed / Stripped)';
  }
  if (key === 'if_upgrade_advertised') {
    if (isBaseline) return 'Advertised (98%)';
    return num >= 0.5 ? 'YES (Advertised)' : 'NO (Not Advertised / Stripped)';
  }
  if (key === 'if_upgrade_requested') {
    if (isBaseline) return 'Requested (95%)';
    return num >= 0.5 ? 'YES (Requested)' : 'NO (Not Requested)';
  }

  // 3. Encryption Modes
  if (key === 'if_encryption_plaintext') {
    if (isBaseline) return 'Encrypted / TLS Required';
    return num >= 0.5 ? 'YES (Unencrypted Stream)' : 'NO (Encrypted)';
  }
  if (key === 'if_encryption_starttls') {
    if (isBaseline) return 'Standard (85%)';
    return num >= 0.5 ? 'YES (Explicit STARTTLS)' : 'NO';
  }
  if (key === 'if_encryption_implicit') {
    if (isBaseline) return 'Direct TLS (15%)';
    return num >= 0.5 ? 'YES (Direct TLS Tunnel)' : 'NO';
  }

  // 4. Protocol Types
  if (key === 'if_protocol_smtp') {
    if (isBaseline) return 'SMTP Baseline';
    return num >= 0.5 ? 'SMTP (Active)' : 'Other Protocol';
  }
  if (key === 'if_protocol_imap') {
    if (isBaseline) return 'IMAP Baseline';
    return num >= 0.5 ? 'IMAP (Active)' : 'Other Protocol';
  }
  if (key === 'if_protocol_pop3') {
    if (isBaseline) return 'POP3 Baseline';
    return num >= 0.5 ? 'POP3 (Active)' : 'Other Protocol';
  }

  // 5. TLS Version (Ordinal: 0=Plaintext/SSLv2, 1=SSLv3, 2=TLS1.0, 3=TLS1.1, 4=TLS1.2, 5=TLS1.3)
  if (key === 'if_tls_version_numeric') {
    let label = 'Plaintext (No TLS)';
    if (num >= 4.5 || num === 1.3) label = 'TLS 1.3 (Modern)';
    else if ((num >= 3.5 && num < 4.5) || num === 1.2) label = 'TLS 1.2 (Standard)';
    else if ((num >= 2.5 && num < 3.5) || num === 1.1) label = 'TLS 1.1 (Deprecated)';
    else if ((num >= 1.5 && num < 2.5) || num === 1.0) label = 'TLS 1.0 (Deprecated)';
    else if (num > 0 && num < 1.5) label = 'Legacy SSL (Insecure)';

    if (isBaseline) return `Expected ${label}`;
    return label;
  }

  // 6. Cipher Suite Strength (0=Weak, 1=Moderate, 2=Strong)
  if (key === 'if_cipher_strength') {
    if (num >= 1.5) return isBaseline ? 'Strong (AEAD Benchmark)' : 'Strong (AEAD / GCM)';
    if (num >= 0.5) return isBaseline ? 'Moderate Suite' : 'Moderate (Legacy CBC)';
    return isBaseline ? 'Weak / Deprecated' : 'Weak / Export / None';
  }

  // 7. Perfect Forward Secrecy (PFS)
  if (key === 'if_pfs_present') {
    if (isBaseline) return 'Standard (90%)';
    return num >= 0.5 ? 'YES (ECDHE/DHE Active)' : 'NO (Static RSA Key)';
  }

  // 8. TLS Handshake Incomplete
  if (key === 'if_tls_handshake_incomplete') {
    if (isBaseline) return 'Completed (99%)';
    return num >= 0.5 ? 'YES (Incomplete / Aborted)' : 'NO (Complete Handshake)';
  }

  // 9. Certificate Visibility & Attributes
  if (key === 'if_cert_visible') {
    if (isBaseline) return 'Observable (95%)';
    return num >= 0.5 ? 'YES (Observed in Handshake)' : 'NO (Hidden / Not Presented)';
  }
  if (key === 'if_cert_key_size') {
    if (num <= 0) return isBaseline ? '2048-bit (Standard)' : 'None / Not Seen';
    const rounded = Math.round(num);
    const suffix = rounded < 2048 ? ' (Weak Key)' : '';
    if (isBaseline) return `~${rounded}-bit (Standard)`;
    return `${rounded}-bit${suffix}`;
  }
  if (key === 'if_cert_self_signed') {
    if (isBaseline) return 'Rare (< 1% / CA Verified)';
    return num >= 0.5 ? 'YES (Self-Signed / Untrusted)' : 'No (CA Verified)';
  }
  if (key === 'if_cert_validity_days') {
    const days = Math.round(num);
    if (days < 0) return isBaseline ? 'Valid (Positive Days)' : `${Math.abs(days)} days ago (Expired)`;
    if (days === 0) return isBaseline ? 'Valid (Positive Days)' : '0 days (Expired/None)';
    if (isBaseline) return `~${days} days valid`;
    return `+${days} days remaining`;
  }
  if (key === 'if_cert_key_algo_rsa') {
    if (isBaseline) return 'Standard (85%)';
    return num >= 0.5 ? 'YES (RSA Key)' : 'NO (Non-RSA)';
  }
  if (key === 'if_cert_key_algo_ec') {
    if (isBaseline) return 'Modern (15%)';
    return num >= 0.5 ? 'YES (ECDSA Key)' : 'NO (Non-EC)';
  }

  // 10. Packet & Session Telemetry
  if (key === 'if_session_duration') {
    const formatted = num < 1 ? `${Math.round(num * 1000)}ms` : `${num.toFixed(1)}s`;
    return isBaseline ? `~${formatted}` : formatted;
  }
  if (key === 'if_packet_ratio') {
    const pct = Math.round(num * 100);
    return isBaseline ? `~${pct}% (Balanced)` : `${pct}% client`;
  }
  if (key === 'if_packet_count') {
    const count = Math.round(num);
    return isBaseline ? `~${count} packets` : `${count} packets`;
  }
  if (key === 'if_client_packet_count') {
    const count = Math.round(num);
    return isBaseline ? `~${count} client pkts` : `${count} client pkts`;
  }
  if (key === 'if_server_packet_count') {
    const count = Math.round(num);
    return isBaseline ? `~${count} server pkts` : `${count} server pkts`;
  }
  if (key === 'if_tcp_reset_count') {
    const count = Math.round(num);
    if (isBaseline) return `${count} resets (Normal: 0)`;
    return count > 0 ? `${count} RST packets` : '0 resets';
  }
  if (key === 'if_session_complete') {
    if (isBaseline) return 'Clean Teardown (95%)';
    return num >= 0.5 ? 'YES (Clean TCP Teardown)' : 'NO (Abrupt / Partial Session)';
  }

  // 11. Security Finding Counts
  if (key === 'if_finding_count') {
    const count = Math.round(num);
    if (isBaseline) return `${count} findings (0 normal)`;
    return `${count} findings`;
  }
  if (key === 'if_high_sev_count') {
    const count = Math.round(num);
    if (isBaseline) return '0 (Clean baseline)';
    return count > 0 ? `${count} critical/high` : '0';
  }
  if (key === 'if_medium_sev_count') {
    const count = Math.round(num);
    if (isBaseline) return '0 (Clean baseline)';
    return count > 0 ? `${count} medium` : '0';
  }

  // Universal fallback for any integer vs float
  if (Math.abs(num - Math.round(num)) < 0.001) {
    return isBaseline ? `~${Math.round(num)}` : `${Math.round(num)}`;
  }
  return isBaseline ? `~${num.toFixed(1)}` : num.toFixed(2);
}

/**
 * Converts raw Isolation Forest decision score into an intuitive 0–100 Anomaly Index.
 *  - 0–30: Standard Baseline (Green) - Calm, healthy normal traffic
 *  - 31–60: Normal Variance (Blue/Slate)
 *  - 61–85: Elevated Anomaly (Amber) - Notable behavioral divergence
 *  - 86–100: Severe Outlier (Red)
 */
function getAnomalyIndex(score, isAnom) {
  if (typeof score !== 'number') return null;
  if (isAnom) {
    const clamped = Math.max(-0.4, Math.min(0, score));
    const ratio = Math.abs(clamped) / 0.4;
    return Math.min(98, Math.max(70, Math.round(70 + ratio * 28))); // 70 to 98
  } else {
    const clamped = Math.max(0, Math.min(0.4, score));
    const ratio = clamped / 0.4;
    return Math.min(25, Math.max(8, Math.round(18 - ratio * 10))); // 8 to 18 (calm green)
  }
}

/**
 * AnomalyDetectionCard
 *
 * Renders the Isolation Forest anomaly assessment at both PCAP-level
 * and per-session level. Conforms strictly to SecureMailScope design
 * system tokens and contract formats.
 */
export default function AnomalyDetectionCard({
  anomalyAssessment,
  sessions = [],
  findings = [],
  onSelectSession,
  summaryOnly = false,
  onViewAllAnomalies,
  analysisId = null,
}) {
  const [expandedSessionId, setExpandedSessionId] = useState(null);
  const [filterType, setFilterType] = useState('ALL'); // 'ALL' | 'ANOMALOUS' | 'BASELINE'
  const [protocolFilter, setProtocolFilter] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [debouncedSearch, setDebouncedSearch] = useState('');

  // Sorting: Default to decision_score ASC (lowest score = most anomalous in Isolation Forest)
  const [sortBy, setSortBy] = useState('decision_score');
  const [sortOrder, setSortOrder] = useState('ASC');

  // Pagination
  const [currentPage, setCurrentPage] = useState(1);

  // Server-side state
  const [serverData, setServerData] = useState(null);
  const [isLoading, setIsLoading] = useState(false);

  // Debounce search input
  useEffect(() => {
    const handler = setTimeout(() => {
      setDebouncedSearch(searchQuery.trim());
      setCurrentPage(1);
    }, 250);
    return () => clearTimeout(handler);
  }, [searchQuery]);

  // Server-side data fetching
  useEffect(() => {
    if (!analysisId || summaryOnly) return;

    let isMounted = true;
    setIsLoading(true);

    analysisApi
      .getSessions(analysisId, {
        page: currentPage,
        limit: PAGE_SIZE,
        search: debouncedSearch,
        protocol: protocolFilter,
        anomaly: filterType,
        sortBy,
        sortOrder,
      })
      .then((data) => {
        if (isMounted) {
          setServerData(data);
          setIsLoading(false);
        }
      })
      .catch(() => {
        if (isMounted) {
          setIsLoading(false);
        }
      });

    return () => {
      isMounted = false;
    };
  }, [
    analysisId,
    summaryOnly,
    currentPage,
    debouncedSearch,
    protocolFilter,
    filterType,
    sortBy,
    sortOrder,
  ]);

  if (!anomalyAssessment && (!sessions || sessions.length === 0)) {
    return null;
  }

  // Extract aggregate metrics with fallbacks
  const totalSessions = anomalyAssessment?.total_sessions ?? sessions.length;
  const anomalousCount =
    anomalyAssessment?.anomalous_count ??
    sessions.filter((s) => s?.anomaly?.is_anomalous).length;
  const baselineCount =
    anomalyAssessment?.within_baseline_count ??
    sessions.filter((s) => s?.anomaly?.is_anomalous === false).length;
  const overallStatus =
    anomalyAssessment?.overall_status ||
    (anomalousCount > 0 ? 'ANOMALIES_DETECTED' : 'ALL_WITHIN_BASELINE');

  // Client-side fallback filtering & sorting
  const clientFilteredSessions = useMemo(() => {
    const query = debouncedSearch.toLowerCase();

    const filtered = (sessions || []).filter((session) => {
      if (filterType === 'ANOMALOUS' && session?.anomaly?.is_anomalous !== true) {
        return false;
      }
      if (filterType === 'BASELINE' && session?.anomaly?.is_anomalous !== false) {
        return false;
      }

      const protocol = (session.protocol || '').toUpperCase();
      if (protocolFilter !== 'ALL' && protocol !== protocolFilter) {
        return false;
      }

      if (query) {
        const matchSearch =
          (session.session_id || '').toLowerCase().includes(query) ||
          (session.client_ip || '').toLowerCase().includes(query) ||
          (session.server_ip || '').toLowerCase().includes(query) ||
          (session.protocol || '').toLowerCase().includes(query) ||
          (session.service || '').toLowerCase().includes(query) ||
          (session?.anomaly?.explanation?.summary || '').toLowerCase().includes(query);
        if (!matchSearch) return false;
      }

      return true;
    });

    const multiplier = sortOrder === 'DESC' ? -1 : 1;
    return [...filtered].sort((a, b) => {
      if (sortBy === 'decision_score' || sortBy === 'score') {
        const sA = a.anomaly?.decision_score ?? 999;
        const sB = b.anomaly?.decision_score ?? 999;
        return (sA - sB) * multiplier;
      }
      if (sortBy === 'anomaly') {
        const anomA = a.anomaly?.is_anomalous ? 1 : 0;
        const anomB = b.anomaly?.is_anomalous ? 1 : 0;
        return (anomB - anomA) * multiplier;
      }
      if (sortBy === 'session_id') {
        return (a.session_id || '').localeCompare(b.session_id || '') * multiplier;
      }
      if (sortBy === 'protocol') {
        return (a.protocol || '').localeCompare(b.protocol || '') * multiplier;
      }
      if (sortBy === 'tcp_stream') {
        return ((a.tcp_stream ?? 0) - (b.tcp_stream ?? 0)) * multiplier;
      }
      return 0;
    });
  }, [sessions, filterType, protocolFilter, debouncedSearch, sortBy, sortOrder]);

  const clientPaginatedSessions = useMemo(() => {
    const start = (currentPage - 1) * PAGE_SIZE;
    return clientFilteredSessions.slice(start, start + PAGE_SIZE);
  }, [clientFilteredSessions, currentPage]);

  const isServerSide = Boolean(analysisId && serverData && !summaryOnly);

  const displaySessions = isServerSide
    ? serverData.items || []
    : clientPaginatedSessions;

  const totalFilteredSessions = isServerSide
    ? serverData.pagination.total
    : clientFilteredSessions.length;

  const totalPages = isServerSide
    ? serverData.pagination.totalPages
    : Math.ceil(clientFilteredSessions.length / PAGE_SIZE) || 1;

  const hasCustomSort = sortBy !== 'decision_score' || sortOrder !== 'ASC';
  const hasActiveFilters =
    protocolFilter !== 'ALL' ||
    filterType !== 'ALL' ||
    searchQuery.trim() !== '';
  const hasModifications = hasActiveFilters || hasCustomSort;

  const resetAll = () => {
    setFilterType('ALL');
    setProtocolFilter('ALL');
    setSearchQuery('');
    setDebouncedSearch('');
    setSortBy('decision_score');
    setSortOrder('ASC');
    setCurrentPage(1);
  };

  const handleSort = (key) => {
    if (sortBy !== key) {
      setSortBy(key);
      setSortOrder('ASC');
    } else if (sortOrder === 'ASC') {
      setSortOrder('DESC');
    } else {
      // 3rd click: Reset to default decision_score ASC
      setSortBy('decision_score');
      setSortOrder('ASC');
    }
    setCurrentPage(1);
  };

  const toggleExpand = (sessionId) => {
    setExpandedSessionId((prev) => (prev === sessionId ? null : sessionId));
  };

  return (
    <div
      id="anomaly-detection-card"
      className="w-full rounded-2xl border border-slate-200/80 dark:border-slate-800 bg-white dark:bg-slate-900 shadow-sm overflow-hidden transition-all duration-200"
    >
      {/* CARD HEADER */}
      <div className="border-b border-slate-100 dark:border-slate-800 bg-gradient-to-r from-slate-50 via-white to-indigo-50/20 dark:from-slate-900 dark:via-slate-850 dark:to-indigo-950/20 px-6 py-5">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-center gap-3">
            <div
              className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-xl shadow-sm ${
                anomalousCount > 0
                  ? 'bg-amber-500/10 text-amber-600 dark:text-amber-400 border border-amber-500/20 dark:border-amber-500/30'
                  : 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20 dark:border-emerald-500/30'
              }`}
            >
              <Cpu className="h-5 w-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-base font-semibold text-slate-900 dark:text-white tracking-tight">
                  Behavioral Anomaly Detection
                </h3>
                <span className="inline-flex items-center rounded-full bg-slate-100 dark:bg-slate-800 px-2 py-0.5 text-[10px] font-mono font-medium text-slate-600 dark:text-slate-300 border border-slate-200 dark:border-slate-700">
                  Isolation Forest · if-v1
                </span>
              </div>
              <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">
                Unsupervised anomaly isolation detecting rare pattern outliers and traffic anomalies
              </p>
            </div>
          </div>

          {/* STATUS PILL & VIEW ALL ACTION */}
          <div className="flex items-center gap-2.5">
            {summaryOnly ? (
              onViewAllAnomalies && (
                <button
                  type="button"
                  onClick={onViewAllAnomalies}
                  className="inline-flex items-center gap-1 text-xs font-semibold text-brand-600 dark:text-brand-400 hover:text-brand-700 dark:hover:text-brand-300 transition-colors"
                >
                  <span>View breakdown</span>
                  <ChevronRight className="h-3.5 w-3.5" />
                </button>
              )
            ) : overallStatus === 'ANOMALIES_DETECTED' ? (
              <span className="inline-flex items-center gap-1.5 rounded-full border border-amber-200 dark:border-amber-800/60 bg-amber-50 dark:bg-amber-950/50 px-3 py-1 text-xs font-semibold text-amber-800 dark:text-amber-300">
                <span className="h-2 w-2 rounded-full bg-amber-500 animate-pulse" />
                {anomalousCount} Outlier{anomalousCount === 1 ? '' : 's'} Isolated
              </span>
            ) : overallStatus === 'MODEL_UNAVAILABLE' ? (
              <span className="inline-flex items-center gap-1.5 rounded-full border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 px-3 py-1 text-xs font-semibold text-slate-600 dark:text-slate-400">
                <HelpCircle className="h-3.5 w-3.5" />
                Model Unavailable
              </span>
            ) : (
              <span className="inline-flex items-center gap-1.5 rounded-full border border-emerald-200 dark:border-emerald-800/60 bg-emerald-50 dark:bg-emerald-950/50 px-3 py-1 text-xs font-semibold text-emerald-800 dark:text-emerald-300">
                <CheckCircle2 className="h-3.5 w-3.5" />
                All Within Baseline
              </span>
            )}
          </div>
        </div>
      </div>

      {/* METRICS STRIP */}
      <div className={`grid grid-cols-2 divide-x divide-y sm:divide-y-0 divide-slate-100 dark:divide-slate-800 sm:grid-cols-4 bg-slate-50/50 dark:bg-slate-850/50 ${summaryOnly ? '' : 'border-b border-slate-100 dark:border-slate-800'}`}>
        <div className="p-4 sm:px-6">
          <p className="text-[11px] font-medium uppercase tracking-wider text-slate-500 dark:text-slate-400">
            Total Analyzed
          </p>
          <p className="mt-1 text-xl font-bold text-slate-900 dark:text-white font-mono">
            {totalSessions}
          </p>
          <span className="text-[10px] text-slate-400 dark:text-slate-500">Reconstructed TCP streams</span>
        </div>

        <div className="p-4 sm:px-6">
          <p className="text-[11px] font-medium uppercase tracking-wider text-slate-500 dark:text-slate-400">
            Anomalous
          </p>
          <p
            className={`mt-1 text-xl font-bold font-mono ${
              anomalousCount > 0 ? 'text-amber-600 dark:text-amber-400' : 'text-slate-700 dark:text-slate-300'
            }`}
          >
            {anomalousCount}
          </p>
          <span className="text-[10px] text-slate-400 dark:text-slate-500">Exceeds isolation threshold</span>
        </div>

        <div className="p-4 sm:px-6">
          <p className="text-[11px] font-medium uppercase tracking-wider text-slate-500 dark:text-slate-400">
            Within Baseline
          </p>
          <p className="mt-1 text-xl font-bold text-emerald-600 dark:text-emerald-400 font-mono">
            {baselineCount}
          </p>
          <span className="text-[10px] text-slate-400 dark:text-slate-500">Normal distribution bounds</span>
        </div>

        <div className="p-4 sm:px-6">
          <p className="text-[11px] font-medium uppercase tracking-wider text-slate-500 dark:text-slate-400">
            Feature Dimension
          </p>
          <p className="mt-1 text-xl font-bold text-indigo-600 dark:text-indigo-400 font-mono">
            30
          </p>
          <span className="text-[10px] text-slate-400 dark:text-slate-500">Features per session vector</span>
        </div>
      </div>

      {/* FULL BREAKDOWN: FILTER TABS, CONTROLS & SESSIONS LIST */}
      {!summaryOnly && (
        <div className="p-6">
          {/* HEADER */}
          <div className="mb-4">
            <h4 className="text-sm font-semibold text-slate-800 dark:text-slate-200 flex items-center gap-2">
              <Layers className="h-4 w-4 text-slate-500 dark:text-slate-400" />
              <span>Session Anomaly Breakdown</span>
              {isLoading && (
                <Loader2 className="h-3.5 w-3.5 animate-spin text-brand-600 dark:text-brand-400" />
              )}
            </h4>
          </div>

          {/* CONTROLS BAR: SEARCH & PROTOCOL (LEFT) + ANOMALY FILTER PILLS (RIGHT) */}
          <div className="mb-4 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <div className="flex flex-wrap items-center gap-2">
              {/* SEARCH */}
              <div className="relative w-full sm:w-[310px] shrink-0">
                <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-400 dark:text-slate-500" />
                <input
                  type="text"
                  placeholder="Search anomalies by ID, IP, protocol..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="h-9 w-full rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 pl-9 pr-8 text-xs text-slate-700 dark:text-slate-200 shadow-sm transition placeholder:text-slate-400 dark:placeholder:text-slate-500 hover:border-slate-300 dark:hover:border-slate-700 focus:border-brand-500 focus:outline-none focus:ring-2 focus:ring-brand-500/10"
                  aria-label="Search anomalies"
                />
                {searchQuery && (
                  <button
                    type="button"
                    onClick={() => setSearchQuery('')}
                    className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 dark:hover:text-slate-300 p-0.5 cursor-pointer"
                    aria-label="Clear search"
                  >
                    <X className="h-3.5 w-3.5" />
                  </button>
                )}
              </div>

              {/* PROTOCOL */}
              <select
                value={protocolFilter}
                onChange={(e) => {
                  setProtocolFilter(e.target.value);
                  setCurrentPage(1);
                }}
                className="h-9 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 px-3 text-xs font-medium text-slate-700 dark:text-slate-200 shadow-sm transition hover:border-slate-300 dark:hover:border-slate-700 focus:border-brand-500 focus:outline-none focus:ring-2 focus:ring-brand-500/10 cursor-pointer shrink-0"
                aria-label="Filter by protocol"
              >
                <option value="ALL">All protocols</option>
                <option value="SMTP">SMTP</option>
                <option value="IMAP">IMAP</option>
                <option value="POP3">POP3</option>
              </select>

              {/* RESET BUTTON */}
              {hasModifications && (
                <button
                  type="button"
                  onClick={resetAll}
                  className="h-9 inline-flex items-center gap-1.5 rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 px-3 text-xs font-medium text-slate-600 dark:text-slate-300 shadow-sm hover:bg-slate-50 dark:hover:bg-slate-700 hover:border-slate-300 dark:hover:border-slate-600 transition shrink-0 cursor-pointer"
                  title="Reset all filters and sorting"
                  aria-label="Reset all filters and sorting"
                >
                  <RotateCcw className="h-3.5 w-3.5 text-slate-400 dark:text-slate-400" />
                  <span>Reset</span>
                </button>
              )}
            </div>

            {/* FILTER BUTTONS (ALL / ANOMALOUS / BASELINE) ON HORIZONTALLY SAME POSITION */}
            <div className="flex items-center rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 p-0.5 text-xs font-medium shrink-0 self-start sm:self-auto">
              <button
                type="button"
                onClick={() => {
                  setFilterType('ALL');
                  setCurrentPage(1);
                }}
                className={`rounded-md px-2.5 py-1 transition-colors cursor-pointer ${
                  filterType === 'ALL'
                    ? 'bg-white dark:bg-slate-900 text-slate-900 dark:text-white shadow-sm font-semibold'
                    : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                }`}
              >
                All ({totalSessions})
              </button>
              <button
                type="button"
                onClick={() => {
                  setFilterType('ANOMALOUS');
                  setCurrentPage(1);
                }}
                className={`rounded-md px-2.5 py-1 transition-colors cursor-pointer ${
                  filterType === 'ANOMALOUS'
                    ? 'bg-white dark:bg-slate-900 text-amber-700 dark:text-amber-400 shadow-sm font-semibold'
                    : 'text-slate-600 dark:text-slate-400 hover:text-amber-700 dark:hover:text-amber-400'
                }`}
              >
                Anomalous ({anomalousCount})
              </button>
              <button
                type="button"
                onClick={() => {
                  setFilterType('BASELINE');
                  setCurrentPage(1);
                }}
                className={`rounded-md px-2.5 py-1 transition-colors cursor-pointer ${
                  filterType === 'BASELINE'
                    ? 'bg-white dark:bg-slate-900 text-emerald-700 dark:text-emerald-400 shadow-sm font-semibold'
                    : 'text-slate-600 dark:text-slate-400 hover:text-emerald-700 dark:hover:text-emerald-400'
                }`}
              >
                Baseline ({baselineCount})
              </button>
            </div>
          </div>

          {/* ANOMALY SESSIONS TABLE */}
          <div className="overflow-hidden rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 shadow-xs">
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse min-w-[760px]">
                <thead>
                  <tr className="border-b border-slate-200 dark:border-slate-800 bg-slate-50/80 dark:bg-slate-850/80">
                    <TableHeader
                      sortKey="session_id"
                      currentSort={sortBy}
                      currentOrder={sortOrder}
                      onSort={handleSort}
                    >
                      Session
                    </TableHeader>

                    <TableHeader
                      sortKey="protocol"
                      currentSort={sortBy}
                      currentOrder={sortOrder}
                      onSort={handleSort}
                    >
                      Protocol
                    </TableHeader>

                    <TableHeader>
                      Connection
                    </TableHeader>

                    <TableHeader
                      sortKey="anomaly"
                      currentSort={sortBy}
                      currentOrder={sortOrder}
                      onSort={handleSort}
                    >
                      Status
                    </TableHeader>

                    <TableHeader
                      sortKey="decision_score"
                      currentSort={sortBy}
                      currentOrder={sortOrder}
                      onSort={handleSort}
                    >
                      Anomaly Score
                    </TableHeader>

                    <TableHeader align="right">
                      Action
                    </TableHeader>
                  </tr>
                </thead>

                <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                  {displaySessions.length === 0 ? (
                    <tr>
                      <td colSpan="6" className="px-6 py-12 text-center">
                        <div className="mx-auto flex max-w-xs flex-col items-center">
                          <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-850">
                            <CheckCircle2 className="h-5 w-5 text-slate-400 dark:text-slate-500" />
                          </div>
                          <p className="mt-3 text-xs font-semibold text-slate-800 dark:text-slate-200">
                            No sessions match filter
                          </p>
                          <p className="mt-1 text-[11px] leading-5 text-slate-500 dark:text-slate-400">
                            Try changing the search term or switching the anomaly filter.
                          </p>
                          {hasModifications && (
                            <button
                              type="button"
                              onClick={resetAll}
                              className="mt-3 text-xs font-semibold text-brand-600 dark:text-brand-400 hover:text-brand-700 dark:hover:text-brand-300 cursor-pointer"
                            >
                              Reset filters
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  ) : (
                    displaySessions.map((session) => {
                      const anomaly = session?.anomaly;
                      const isAnom = anomaly?.is_anomalous === true;
                      const isExpanded = expandedSessionId === session.session_id;

                      return (
                        <React.Fragment key={session.session_id}>
                          <tr
                            onClick={() => toggleExpand(session.session_id)}
                            className={`transition-colors cursor-pointer select-none ${
                              isAnom
                                ? isExpanded
                                  ? 'bg-amber-100/40 dark:bg-amber-950/40'
                                  : 'bg-amber-50/20 dark:bg-amber-950/15 hover:bg-amber-50/50 dark:hover:bg-amber-950/30'
                                : isExpanded
                                ? 'bg-slate-50 dark:bg-slate-800/60'
                                : 'hover:bg-slate-50/80 dark:hover:bg-slate-850/60'
                            }`}
                          >
                            {/* SESSION */}
                            <td className="px-4 py-3.5 text-xs">
                              <div className="flex items-center gap-2">
                                <span className="font-mono font-bold text-slate-900 dark:text-white">
                                  {session.session_id}
                                </span>
                                {session.tcp_stream !== null && session.tcp_stream !== undefined && (
                                  <span className="rounded bg-slate-100 dark:bg-slate-800 px-1.5 py-0.5 font-mono text-[10px] text-slate-500 dark:text-slate-400 border border-slate-200 dark:border-slate-700">
                                    #{session.tcp_stream}
                                  </span>
                                )}
                              </div>
                            </td>

                            {/* PROTOCOL */}
                            <td className="px-4 py-3.5 text-xs">
                              <span
                                className={`inline-flex items-center rounded-md px-2 py-0.5 font-mono text-[11px] font-bold ${
                                  isAnom
                                    ? 'bg-amber-100 dark:bg-amber-950/70 text-amber-800 dark:text-amber-300 border border-amber-200 dark:border-amber-800'
                                    : 'bg-emerald-100 dark:bg-emerald-950/70 text-emerald-800 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-800'
                                }`}
                              >
                                {session.protocol || 'TCP'}
                              </span>
                            </td>

                            {/* CONNECTION */}
                            <td className="px-4 py-3.5 text-xs whitespace-nowrap">
                              <div className="font-mono text-[11px] text-slate-600 dark:text-slate-400">
                                <span className="text-slate-900 dark:text-slate-200 font-medium">
                                  {session.client_ip}
                                </span>
                                <span className="text-slate-400 dark:text-slate-500">
                                  :{session.client_port}
                                </span>
                                <span className="mx-1.5 text-slate-300 dark:text-slate-600 font-sans">
                                  →
                                </span>
                                <span className="text-slate-900 dark:text-slate-200 font-medium">
                                  {session.server_ip}
                                </span>
                                <span className="text-slate-400 dark:text-slate-500">
                                  :{session.server_port}
                                </span>
                              </div>
                            </td>

                            {/* STATUS */}
                            <td className="px-4 py-3.5 text-xs whitespace-nowrap">
                              {isAnom ? (
                                <span className="inline-flex items-center gap-1.5 rounded-full bg-amber-100 dark:bg-amber-950/60 px-2.5 py-0.5 text-[11px] font-semibold text-amber-800 dark:text-amber-300 border border-amber-200 dark:border-amber-800">
                                  <AlertTriangle className="h-3 w-3" />
                                  ANOMALOUS
                                </span>
                              ) : (
                                <span className="inline-flex items-center gap-1.5 rounded-full bg-emerald-50 dark:bg-emerald-950/60 px-2.5 py-0.5 text-[11px] font-semibold text-emerald-700 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-800">
                                  <CheckCircle2 className="h-3 w-3" />
                                  BASELINE
                                </span>
                              )}
                            </td>

                            {/* ANOMALY SCORE */}
                            <td className="px-4 py-3.5 text-xs whitespace-nowrap">
                              {typeof anomaly?.decision_score === 'number' ? (
                                (() => {
                                  const index = getAnomalyIndex(anomaly.decision_score, isAnom);
                                  return (
                                    <div className="flex items-center gap-2">
                                      {/* 0-100 Anomaly Index Badge */}
                                      <span
                                        className={`inline-flex items-center gap-1.5 font-mono text-xs font-bold px-2.5 py-1 rounded-lg border ${
                                          isAnom
                                            ? index >= 85
                                              ? 'text-rose-700 dark:text-rose-300 bg-rose-50 dark:bg-rose-950/50 border-rose-200 dark:border-rose-800'
                                              : 'text-amber-800 dark:text-amber-300 bg-amber-50 dark:bg-amber-950/50 border-amber-300 dark:border-amber-800'
                                            : 'text-emerald-800 dark:text-emerald-300 bg-emerald-50 dark:bg-emerald-950/50 border-emerald-200 dark:border-emerald-800'
                                        }`}
                                        title={`Anomaly Index: ${index}/100 · Underlying ML Score: ${anomaly.decision_score.toFixed(3)}`}
                                      >
                                        <span className={`h-1.5 w-1.5 rounded-full ${isAnom ? 'bg-amber-500' : 'bg-emerald-500'}`} />
                                        <span>{index}</span>
                                        <span className="text-[10px] font-sans font-normal opacity-60">/100</span>
                                      </span>

                                      {/* Clear Status Indicator */}
                                      <span className={`text-[11px] font-medium ${isAnom ? 'text-amber-700 dark:text-amber-400 font-semibold' : 'text-slate-500 dark:text-slate-400'}`}>
                                        {isAnom ? (index >= 85 ? 'Severe Outlier' : 'Elevated Anomaly') : 'Within Baseline'}
                                      </span>
                                    </div>
                                  );
                                })()
                              ) : (
                                <span className="text-slate-400 dark:text-slate-500 font-mono text-xs">—</span>
                              )}
                            </td>

                            {/* ACTION */}
                            <td className="px-4 py-3.5 text-xs text-right whitespace-nowrap">
                              <button
                                type="button"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  toggleExpand(session.session_id);
                                }}
                                className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-lg text-xs font-medium transition cursor-pointer border ${
                                  isExpanded
                                    ? 'bg-slate-100 dark:bg-slate-800 text-slate-900 dark:text-white border-slate-300 dark:border-slate-700'
                                    : 'bg-white dark:bg-slate-900 text-slate-600 dark:text-slate-400 border-slate-200 dark:border-slate-800 hover:bg-slate-50 dark:hover:bg-slate-800 hover:text-slate-900 dark:hover:text-white'
                                }`}
                                aria-label={isExpanded ? 'Hide details' : 'View details'}
                                title={isExpanded ? 'Hide details' : 'View explanation & deviations'}
                              >
                                <span>{isExpanded ? 'Hide' : 'Details'}</span>
                                {isExpanded ? (
                                  <ChevronUp className="h-3.5 w-3.5" />
                                ) : (
                                  <ChevronDown className="h-3.5 w-3.5" />
                                )}
                              </button>
                            </td>
                          </tr>

                          {/* EXPANDED DETAILS ACCORDION ROW */}
                          {isExpanded && (
                            <tr className="bg-slate-50/70 dark:bg-slate-850/50 border-b border-slate-200 dark:border-slate-800">
                              <td colSpan="6" className="p-4 sm:p-5">
                                <div className="space-y-4">
                                  {/* EXPLANATION NARRATIVE */}
                                  <div>
                                    <h5 className="text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400 flex items-center gap-1.5">
                                      <Info className="h-3.5 w-3.5 text-slate-400" />
                                      Behavioral Assessment & Explanation
                                    </h5>
                                    <div className="mt-1 bg-white dark:bg-slate-900 p-3.5 rounded-xl border border-slate-200/80 dark:border-slate-800 shadow-2xs">
                                      <p className="text-xs leading-relaxed text-slate-700 dark:text-slate-300">
                                        {anomaly?.explanation?.summary ||
                                          (isAnom
                                            ? 'This session was classified as anomalous because its communication patterns deviate notably from standard enterprise mail traffic.'
                                            : "This session's communication dynamics are completely within standard baseline expectations.")}
                                      </p>
                                    </div>
                                  </div>

                                  {/* STATISTICAL DEVIATIONS */}
                                  {Array.isArray(anomaly?.explanation?.deviations) &&
                                    anomaly.explanation.deviations.length > 0 && (
                                      <div>
                                        <h5 className="text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400 flex items-center gap-1.5 mb-2">
                                          <Sliders className="h-3.5 w-3.5 text-slate-400" />
                                          Observed Traffic Deviations vs Normal Baseline
                                        </h5>
                                        <div className="grid gap-2.5 sm:grid-cols-2">
                                          {anomaly.explanation.deviations.map((dev, idx) => {
                                            const featureKey = dev.feature || dev.name || 'Traffic Metric';
                                            const baselineVal = dev.baseline_median !== undefined
                                              ? dev.baseline_median
                                              : dev.baseline_mean;
                                            const comparisonText = dev.comparison || (isAnom ? 'Deviates from baseline' : 'Within expected range');
                                            const isAbove = String(comparisonText).toLowerCase().includes('above');
                                            const isBelow = String(comparisonText).toLowerCase().includes('below');

                                            const friendlyName =
                                              FRIENDLY_FEATURE_NAMES[featureKey] ||
                                              FRIENDLY_FEATURE_NAMES[`if_${featureKey}`] ||
                                              featureKey;

                                            return (
                                              <div
                                                key={idx}
                                                className="rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 p-3.5 text-xs shadow-2xs space-y-2"
                                              >
                                                <div className="flex items-center justify-between font-mono text-[11px] gap-2">
                                                  <span className="font-semibold text-slate-800 dark:text-slate-200 truncate" title={friendlyName}>
                                                    {friendlyName}
                                                  </span>
                                                  <span
                                                    className={`px-2 py-0.5 rounded-md text-[10px] font-sans font-semibold uppercase tracking-wider ${
                                                      isAbove
                                                        ? 'bg-amber-100 dark:bg-amber-950/70 text-amber-800 dark:text-amber-300 border border-amber-300 dark:border-amber-800'
                                                        : isBelow
                                                        ? 'bg-indigo-100 dark:bg-indigo-950/70 text-indigo-800 dark:text-indigo-300 border border-indigo-300 dark:border-indigo-800'
                                                        : 'bg-slate-100 dark:bg-slate-700 text-slate-700 dark:text-slate-300'
                                                    }`}
                                                  >
                                                    {comparisonText}
                                                  </span>
                                                </div>

                                                {/* VALUE COMPARISON */}
                                                <div className="grid grid-cols-2 gap-2 text-[11px] bg-slate-50 dark:bg-slate-850 p-2.5 rounded-lg border border-slate-100 dark:border-slate-800">
                                                  <div className="border-r border-slate-200 dark:border-slate-700/60 pr-2">
                                                    <span className="text-slate-400 dark:text-slate-500 text-[10px] block font-sans">
                                                      This Session
                                                    </span>
                                                    <span className="font-mono font-bold text-slate-900 dark:text-white text-xs">
                                                      {formatFriendlyValue(featureKey, dev.observed, false)}
                                                    </span>
                                                  </div>
                                                  <div className="pl-1">
                                                    <span className="text-slate-400 dark:text-slate-500 text-[10px] block font-sans">
                                                      Normal Benchmark
                                                    </span>
                                                    <span className="font-mono font-medium text-slate-600 dark:text-slate-300 text-xs">
                                                      {formatFriendlyValue(featureKey, baselineVal, true)}
                                                    </span>
                                                  </div>
                                                </div>

                                                {/* INTERPRETATION NARRATIVE */}
                                                {(dev.description || dev.interpretation) && (
                                                  <p className="text-[11px] leading-relaxed text-slate-600 dark:text-slate-300 pt-0.5">
                                                    {dev.description || dev.interpretation}
                                                  </p>
                                                )}
                                                {dev.description && dev.interpretation && dev.description !== dev.interpretation && (
                                                  <p className="text-[10px] text-slate-400 dark:text-slate-500 italic">
                                                    {dev.interpretation}
                                                  </p>
                                                )}
                                              </div>
                                            );
                                          })}
                                        </div>
                                      </div>
                                    )}

                                  {/* CROSS-REFERENCED DETERMINISTIC FINDINGS */}
                                  {Array.isArray(anomaly?.explanation?.related_findings) &&
                                    anomaly.explanation.related_findings.length > 0 && (
                                      <div>
                                        <h5 className="text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400 flex items-center gap-1.5 mb-1.5">
                                          <ShieldAlert className="h-3.5 w-3.5 text-slate-400" />
                                          Related Rule Engine Findings
                                        </h5>
                                        <div className="flex flex-wrap gap-1.5">
                                          {anomaly.explanation.related_findings.map((fid) => (
                                            <span
                                              key={fid}
                                              className="inline-flex items-center rounded-md bg-rose-50 dark:bg-rose-950/60 px-2 py-0.5 font-mono text-[11px] font-semibold text-rose-700 dark:text-rose-300 border border-rose-200 dark:border-rose-800"
                                            >
                                              {fid}
                                            </span>
                                          ))}
                                        </div>
                                      </div>
                                    )}

                                  {/* ACTION: INSPECT SESSION IN DETAILS DRAWER */}
                                  {onSelectSession && (
                                    <div className="flex justify-end pt-2 border-t border-slate-200 dark:border-slate-800">
                                      <button
                                        type="button"
                                        onClick={(e) => {
                                          e.stopPropagation();
                                          onSelectSession(session);
                                        }}
                                        className="inline-flex items-center gap-1.5 text-xs font-semibold text-brand-600 dark:text-brand-400 hover:text-brand-800 dark:hover:text-brand-300 transition-colors cursor-pointer"
                                      >
                                        Inspect full session telemetry
                                        <ExternalLink className="h-3.5 w-3.5" />
                                      </button>
                                    </div>
                                  )}
                                </div>
                              </td>
                            </tr>
                          )}
                        </React.Fragment>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>

            {/* PAGINATION & TABLE FOOTER */}
            <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between border-t border-slate-100 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-850/50 px-4 py-3.5 text-xs text-slate-500 dark:text-slate-400">
              <div>
                {totalFilteredSessions > 0 ? (
                  <span>
                    Showing{' '}
                    <span className="font-semibold text-slate-700 dark:text-slate-200">
                      {(currentPage - 1) * PAGE_SIZE + 1}
                    </span>{' '}
                    to{' '}
                    <span className="font-semibold text-slate-700 dark:text-slate-200">
                      {Math.min(currentPage * PAGE_SIZE, totalFilteredSessions)}
                    </span>{' '}
                    of{' '}
                    <span className="font-semibold text-slate-700 dark:text-slate-200">
                      {totalFilteredSessions}
                    </span>{' '}
                    sessions
                  </span>
                ) : (
                  <span>0 sessions</span>
                )}
              </div>

              {/* PAGE BUTTONS */}
              {totalPages > 1 && (
                <div className="flex items-center gap-1.5 self-end sm:self-auto">
                  <button
                    type="button"
                    disabled={currentPage <= 1}
                    onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                    className="inline-flex items-center gap-1 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 px-2.5 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-300 shadow-sm transition hover:bg-slate-50 dark:hover:bg-slate-700 disabled:opacity-40 disabled:pointer-events-none cursor-pointer"
                    aria-label="Previous page"
                  >
                    <ChevronLeft className="h-3.5 w-3.5" />
                    <span className="hidden sm:inline">Prev</span>
                  </button>

                  <div className="flex items-center gap-1">
                    {Array.from({ length: totalPages }, (_, i) => i + 1).map((pageNum) => {
                      if (
                        totalPages > 7 &&
                        pageNum !== 1 &&
                        pageNum !== totalPages &&
                        Math.abs(pageNum - currentPage) > 1
                      ) {
                        if (pageNum === 2 || pageNum === totalPages - 1) {
                          return (
                            <span
                              key={pageNum}
                              className="px-1 text-xs text-slate-400 dark:text-slate-500"
                            >
                              …
                            </span>
                          );
                        }
                        return null;
                      }

                      const isActive = pageNum === currentPage;
                      return (
                        <button
                          key={pageNum}
                          type="button"
                          onClick={() => setCurrentPage(pageNum)}
                          className={`h-7 min-w-[28px] rounded-lg px-2 text-xs font-semibold transition cursor-pointer ${
                            isActive
                              ? 'border border-brand-600 bg-brand-600 text-white shadow-sm'
                              : 'border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-700'
                          }`}
                          aria-current={isActive ? 'page' : undefined}
                        >
                          {pageNum}
                        </button>
                      );
                    })}
                  </div>

                  <button
                    type="button"
                    disabled={currentPage >= totalPages}
                    onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
                    className="inline-flex items-center gap-1 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 px-2.5 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-300 shadow-sm transition hover:bg-slate-50 dark:hover:bg-slate-700 disabled:opacity-40 disabled:pointer-events-none cursor-pointer"
                    aria-label="Next page"
                  >
                    <span className="hidden sm:inline">Next</span>
                    <ChevronRight className="h-3.5 w-3.5" />
                  </button>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

/* ===============================================================
   TABLE HEADER COMPONENT
=============================================================== */
function TableHeader({
  children,
  align = 'left',
  sortKey = null,
  currentSort = null,
  currentOrder = 'ASC',
  onSort = null,
  className = '',
}) {
  const isSortable = Boolean(sortKey && onSort);
  const isActive = isSortable && currentSort === sortKey;

  const getSortTooltip = () => {
    if (!isSortable) return undefined;
    if (!isActive) return `Sort by ${children} (ascending)`;
    if (currentOrder === 'ASC') return `Sort by ${children} (descending)`;
    return 'Click to remove sort';
  };

  return (
    <th
      scope="col"
      className={`px-4 py-3 text-[10px] font-semibold uppercase tracking-[0.08em] select-none ${
        align === 'right' ? 'text-right' : 'text-left'
      } ${
        isSortable
          ? 'cursor-pointer transition-colors hover:text-slate-900 dark:hover:text-white'
          : 'text-slate-500 dark:text-slate-400'
      } ${isActive ? 'text-brand-600 dark:text-brand-400 font-bold' : 'text-slate-500 dark:text-slate-400'} ${className}`}
      onClick={isSortable ? () => onSort(sortKey) : undefined}
      title={getSortTooltip()}
      aria-sort={
        isActive
          ? currentOrder === 'ASC'
            ? 'ascending'
            : 'descending'
          : undefined
      }
    >
      <div className={`inline-flex items-center gap-1.5 ${align === 'right' ? 'justify-end' : ''}`}>
        <span>{children}</span>
        {isSortable && (
          <span
            className={`shrink-0 transition-colors ${
              isActive ? 'text-brand-600 dark:text-brand-400' : 'text-slate-400 dark:text-slate-500 opacity-50 hover:opacity-100'
            }`}
          >
            {isActive ? (
              currentOrder === 'DESC' ? (
                <ArrowDown className="h-3 w-3 stroke-[2.5]" />
              ) : (
                <ArrowUp className="h-3 w-3 stroke-[2.5]" />
              )
            ) : (
              <ArrowUpDown className="h-3 w-3" />
            )}
          </span>
        )}
      </div>
    </th>
  );
}
