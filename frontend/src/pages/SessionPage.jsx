import React, { useState, useMemo, useEffect } from 'react';
import { useParams, useNavigate, useLocation, Link } from 'react-router-dom';
import {
  ArrowLeft,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  Lock,
  Key,
  Award,
  EyeOff,
  CheckCircle2,
  HelpCircle,
  Download,
  Copy,
  Check,
  AlertTriangle,
  FileCode,
  ExternalLink,
  ChevronRight,
  ChevronLeft,
  RefreshCw,
  Network,
  ArrowUpRight,
  Activity,
  Layers,
  FileText,
  AlertOctagon,
  Info,
} from 'lucide-react';

import { analysisApi } from '../api/analysisApi';
import { useAnalysis } from '../hooks/useAnalysis';
import StandardsContextSection from '../components/standards/StandardsContextSection';
import LoadingState from '../components/LoadingState';
import ErrorState from '../components/ErrorState';
import {
  formatTriState,
  formatEncryptionMode,
  formatDate,
} from '../utils/formatters';

export default function SessionPage() {
  const { id: analysisId, sessionId } = useParams();
  const navigate = useNavigate();
  const location = useLocation();

  // If session or analysis was passed via navigation state, use as initial cache
  const passedSession = location.state?.session || null;
  const passedAnalysis = location.state?.analysis || null;
  const passedFindings = location.state?.findings || null;

  const {
    analysis,
    loading,
    error,
    fetchAnalysis,
  } = useAnalysis(analysisId, passedAnalysis);

  const [copiedFilter, setCopiedFilter] = useState(false);
  const [copiedClient, setCopiedClient] = useState(false);
  const [copiedServer, setCopiedServer] = useState(false);
  const [isDownloading, setIsDownloading] = useState(false);
  const [downloadError, setDownloadError] = useState(null);
  const [activeSection, setActiveSection] = useState('section-forensics');

  // Smooth scroll to target section
  const scrollToSection = (sectionId) => {
    setActiveSection(sectionId);
    const element = document.getElementById(sectionId);
    if (element) {
      const yOffset = -85;
      const topPos = element.getBoundingClientRect ? element.getBoundingClientRect().top : 0;
      const scrollPos = window.pageYOffset ?? window.scrollY ?? 0;
      const y = topPos + scrollPos + yOffset;
      if (typeof window.scrollTo === 'function') {
        window.scrollTo({ top: y, behavior: 'smooth' });
      }
    }
  };

  // Observe active section on window scroll
  useEffect(() => {
    const handleScroll = () => {
      const sections = ['section-forensics', 'section-standards', 'section-findings'];
      const scrollPos = window.scrollY + 130;
      for (let i = sections.length - 1; i >= 0; i--) {
        const el = document.getElementById(sections[i]);
        if (el && el.offsetTop <= scrollPos) {
          setActiveSection(sections[i]);
          break;
        }
      }
    };
    window.addEventListener('scroll', handleScroll, { passive: true });
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  // Find target session either from passed state or from analysis data
  const session = useMemo(() => {
    if (passedSession && String(passedSession.session_id) === String(sessionId)) {
      return passedSession;
    }
    const found = analysis?.sessions?.find(
      (s) => String(s.session_id) === String(sessionId)
    );
    return found || passedSession || null;
  }, [passedSession, analysis, sessionId]);

  // Extract all sessions for prev/next switcher
  const allSessions = useMemo(() => {
    return analysis?.sessions || (session ? [session] : []);
  }, [analysis, session]);

  const currentIndex = useMemo(() => {
    return allSessions.findIndex(
      (s) => String(s.session_id) === String(sessionId)
    );
  }, [allSessions, sessionId]);

  const prevSession = currentIndex > 0 ? allSessions[currentIndex - 1] : null;
  const nextSession =
    currentIndex >= 0 && currentIndex < allSessions.length - 1
      ? allSessions[currentIndex + 1]
      : null;

  // Findings associated with this session
  const sessionFindings = useMemo(() => {
    const list = passedFindings || analysis?.findings || [];
    if (!sessionId) return [];
    return list.filter((f) => String(f.session_id) === String(sessionId));
  }, [passedFindings, analysis, sessionId]);

  // Ensure analysis is loaded if not already in state
  useEffect(() => {
    if (analysisId && (!analysis || String(analysis.analysis_id) !== String(analysisId))) {
      fetchAnalysis(analysisId);
    }
  }, [analysisId, analysis, fetchAnalysis]);

  // Copy Wireshark Filter
  const wiresharkFilter =
    session?.wireshark_filter ||
    (session?.tcp_stream !== null && session?.tcp_stream !== undefined
      ? `tcp.stream == ${session.tcp_stream}`
      : session?.client_ip && session?.server_ip
      ? `ip.addr == ${session.client_ip} && ip.addr == ${session.server_ip}`
      : null);

  const handleCopyFilter = async () => {
    if (!wiresharkFilter) return;
    try {
      await navigator.clipboard.writeText(wiresharkFilter);
      setCopiedFilter(true);
      setTimeout(() => setCopiedFilter(false), 2000);
    } catch (_) {}
  };

  const handleCopyClient = async () => {
    if (!session?.client_ip) return;
    try {
      await navigator.clipboard.writeText(
        `${session.client_ip}:${session.client_port || ''}`
      );
      setCopiedClient(true);
      setTimeout(() => setCopiedClient(false), 2000);
    } catch (_) {}
  };

  const handleCopyServer = async () => {
    if (!session?.server_ip) return;
    try {
      await navigator.clipboard.writeText(
        `${session.server_ip}:${session.server_port || ''}`
      );
      setCopiedServer(true);
      setTimeout(() => setCopiedServer(false), 2000);
    } catch (_) {}
  };

  // Download isolated session PCAP
  const handleDownloadPcap = async () => {
    if (!analysisId || !session) return;
    setIsDownloading(true);
    setDownloadError(null);
    try {
      const blob = await analysisApi.downloadSessionPcap(
        analysisId,
        session.session_id
      );
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${session.session_id || 'session'}_stream_${session.tcp_stream ?? 0}.pcap`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (err) {
      setDownloadError(err.message || 'Failed to download session capture.');
    } finally {
      setIsDownloading(false);
    }
  };

  // Switch to another session
  const handleSwitchSession = (targetSession) => {
    if (!targetSession) return;
    navigate(`/analysis/${analysisId}/session/${targetSession.session_id}`, {
      state: {
        session: targetSession,
        analysis,
        analysisId,
        findings: analysis?.findings || passedFindings,
      },
    });
  };

  // If analysis is still loading and we have no session data at all
  if (loading && !session) {
    return (
      <div className="mx-auto max-w-7xl px-4 py-16 sm:px-6 lg:px-8">
        <LoadingState message="Reconstructing session forensics from network capture..." />
      </div>
    );
  }

  // If error occurred and no session data
  if (error && !session) {
    return (
      <div className="mx-auto max-w-7xl px-4 py-16 sm:px-6 lg:px-8">
        <ErrorState
          message={error}
          onRetry={() => fetchAnalysis(analysisId)}
        />
        <div className="mt-4 text-center">
          <Link
            to={`/analysis/${analysisId}?tab=sessions`}
            className="inline-flex items-center gap-1.5 text-xs font-semibold text-brand-600 hover:text-brand-700"
          >
            <ArrowLeft className="h-4 w-4" /> Back to Analysis
          </Link>
        </div>
      </div>
    );
  }

  // If analysis finished loading but session not found
  if (!loading && !session) {
    return (
      <div className="mx-auto max-w-4xl px-4 py-16 sm:px-6 lg:px-8 text-center">
        <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl border border-slate-200 bg-white shadow-sm">
          <AlertOctagon className="h-7 w-7 text-amber-500" />
        </div>
        <h2 className="mt-4 text-xl font-bold text-slate-800">
          Session Not Found
        </h2>
        <p className="mt-2 text-sm text-slate-500">
          The requested session <code className="font-mono font-bold text-slate-700">{sessionId}</code> does not exist in capture #{analysisId}.
        </p>
        <div className="mt-6 flex justify-center gap-3">
          <Link
            to={`/analysis/${analysisId}?tab=sessions`}
            className="inline-flex items-center gap-2 rounded-xl bg-brand-600 px-4 py-2.5 text-xs font-semibold text-white shadow-sm transition hover:bg-brand-700"
          >
            <ArrowLeft className="h-4 w-4" />
            Return to Session Table
          </Link>
        </div>
      </div>
    );
  }

  const enc = formatEncryptionMode(session?.security?.encryption_mode);
  const sessionRiskLevel = session.risk?.level || session.risk_label || 'LOW';
  const sessionRiskScore =
    session.risk?.score ??
    (sessionRiskLevel === 'CRITICAL'
      ? 95
      : sessionRiskLevel === 'HIGH'
      ? 80
      : sessionRiskLevel === 'MEDIUM'
      ? 50
      : 15);
  const sessionConfidence = session.risk?.confidence ?? 0.95;
  const isPartial = session.security?.capture_completeness === 'PARTIAL';

  return (
    <div className="min-h-screen bg-slate-50/70 dark:bg-slate-950 pb-20 pt-6">
      <div className="w-full mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 space-y-6">

        {/* =========================================================
            TOP BREADCRUMB & BACK NAVIGATION BAR
        ========================================================== */}
        <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex flex-wrap items-center gap-2 text-xs text-slate-500 dark:text-slate-400">
            <Link
              to="/analysis"
              className="font-medium text-slate-600 dark:text-slate-400 hover:text-brand-600 dark:hover:text-brand-400 transition-colors"
            >
              Analyses
            </Link>
            <ChevronRight className="h-3.5 w-3.5 text-slate-400" />
            <Link
              to={`/analysis/${analysisId}?tab=sessions`}
              state={{ analysis }}
              className="font-medium text-slate-600 dark:text-slate-400 hover:text-brand-600 dark:hover:text-brand-400 transition-colors truncate max-w-[200px]"
              title={analysis?.pcap_filename || analysis?.filename || analysisId}
            >
              {analysis?.pcap_filename || analysis?.filename || `Capture #${analysisId?.slice(0, 8)}`}
            </Link>
            <ChevronRight className="h-3.5 w-3.5 text-slate-400" />
            <span className="font-mono font-bold text-brand-700 bg-brand-50 dark:text-brand-300 dark:bg-brand-950/70 px-2 py-0.5 rounded border border-brand-200 dark:border-brand-800">
              {session.session_id}
            </span>
          </div>

          <div className="flex items-center gap-2.5">
            <Link
              to={`/analysis/${analysisId}?tab=sessions`}
              state={{ analysis }}
              className="inline-flex items-center gap-2 rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 px-3.5 py-2 text-xs font-semibold text-slate-700 dark:text-slate-200 shadow-sm transition-all hover:border-slate-300 dark:hover:border-slate-600 hover:bg-slate-50 dark:hover:bg-slate-700 focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-500/20"
            >
              <ArrowLeft className="h-4 w-4 text-slate-500 dark:text-slate-400" />
              <span>Back to Analysis</span>
            </Link>
          </div>
        </div>

        {/* =========================================================
            SESSION HERO CARD
        ========================================================== */}
        <div className="relative overflow-hidden rounded-2xl border border-slate-200/90 dark:border-slate-800 bg-white dark:bg-slate-900 shadow-sm dark:shadow-soft-dark">
          {/* Subtle gradient banner top */}
          <div className="absolute inset-x-0 top-0 h-1.5 bg-gradient-to-r from-brand-500 via-sky-500 to-indigo-500" />

          <div className="p-6 sm:p-7">
            <div className="flex flex-col gap-6 lg:flex-row lg:items-center lg:justify-between">

              {/* Left Identity */}
              <div className="flex items-start gap-4">
                <div
                  className={`flex h-14 w-14 shrink-0 items-center justify-center rounded-2xl border ${
                    sessionRiskLevel === 'CRITICAL' || sessionRiskLevel === 'HIGH'
                      ? 'border-red-200 dark:border-red-800/60 bg-red-50 dark:bg-red-950/50 text-red-600 dark:text-red-400'
                      : sessionRiskLevel === 'MEDIUM'
                      ? 'border-amber-200 dark:border-amber-800/60 bg-amber-50 dark:bg-amber-950/50 text-amber-600 dark:text-amber-400'
                      : 'border-emerald-200 dark:border-emerald-800/60 bg-emerald-50 dark:bg-emerald-950/50 text-emerald-600 dark:text-emerald-400'
                  }`}
                >
                  <Shield className="h-7 w-7" />
                </div>

                <div className="space-y-1.5">
                  <div className="flex flex-wrap items-center gap-2.5">
                    <h1 className="font-mono text-2xl font-black text-slate-900 dark:text-white tracking-tight">
                      {session.session_id}
                    </h1>

                    {/* Encryption Badge */}
                    <span
                      className={`inline-flex items-center rounded-lg border px-3 py-1 font-mono text-xs font-bold uppercase tracking-wider ${
                        enc.label?.toUpperCase().includes('PLAIN')
                          ? 'border-red-200 dark:border-red-800/60 bg-red-50 dark:bg-red-950/50 text-red-700 dark:text-red-400'
                          : enc.label?.toUpperCase().includes('STARTTLS')
                          ? 'border-sky-200 dark:border-sky-800/60 bg-sky-50 dark:bg-sky-950/50 text-sky-700 dark:text-sky-300'
                          : 'border-yellow-200 dark:border-yellow-800/60 bg-yellow-50 dark:bg-yellow-950/50 text-yellow-700 dark:text-yellow-300'
                      }`}
                    >
                      {enc.label}
                    </span>

                    {/* Stream # */}
                    {session.tcp_stream !== null && session.tcp_stream !== undefined && (
                      <span className="inline-flex items-center gap-1 rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-100 dark:bg-slate-800 px-2.5 py-1 font-mono text-xs font-semibold text-slate-700 dark:text-slate-300">
                        Stream #{session.tcp_stream}
                      </span>
                    )}

                    {/* Protocol */}
                    <span className="inline-flex items-center rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 px-2.5 py-1 font-mono text-xs font-bold text-slate-800 dark:text-slate-200">
                      {session.protocol || 'TCP'}
                    </span>
                  </div>

                  <p className="text-xs text-slate-500 dark:text-slate-400 flex flex-wrap items-center gap-2">
                    <span className="font-semibold text-slate-700 dark:text-slate-300">{session.service || 'email-service'}</span>
                    <span>•</span>
                    <span>Session Security Inspection & Protocol Forensics</span>
                    {session.packet_count && (
                      <>
                        <span>•</span>
                        <span className="font-mono font-medium text-slate-600 dark:text-slate-400">{session.packet_count} packets captured</span>
                      </>
                    )}
                  </p>
                </div>
              </div>

              {/* Right: Risk Assessment Card */}
              <div className="flex flex-wrap items-center gap-4 rounded-xl border border-slate-200/80 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-800/60 p-4 sm:gap-6">
                <div>
                  <p className="text-[10px] font-bold uppercase tracking-wider text-slate-400 dark:text-slate-500">
                    Session Risk Verdict
                  </p>
                  <div className="mt-1 flex items-center gap-2">
                    <span
                      className={`inline-flex items-center rounded-lg border px-2.5 py-0.5 font-mono text-xs font-bold uppercase ${
                        sessionRiskLevel === 'CRITICAL'
                          ? 'border-red-300 dark:border-red-800 bg-red-100/70 dark:bg-red-950/60 text-red-800 dark:text-red-300'
                          : sessionRiskLevel === 'HIGH'
                          ? 'border-orange-300 dark:border-orange-800 bg-orange-100/70 dark:bg-orange-950/60 text-orange-800 dark:text-orange-300'
                          : sessionRiskLevel === 'MEDIUM'
                          ? 'border-amber-300 dark:border-amber-800 bg-amber-100/70 dark:bg-amber-950/60 text-amber-800 dark:text-amber-300'
                          : 'border-emerald-300 dark:border-emerald-800 bg-emerald-100/70 dark:bg-emerald-950/60 text-emerald-800 dark:text-emerald-300'
                      }`}
                    >
                      {sessionRiskLevel}
                    </span>
                    <span className="font-mono text-sm font-extrabold text-slate-800 dark:text-slate-100">
                      {sessionRiskScore}/100
                    </span>
                  </div>
                </div>

                <div className="h-8 w-px bg-slate-200 dark:bg-slate-700" />

                <div>
                  <p className="text-[10px] font-bold uppercase tracking-wider text-slate-400 dark:text-slate-500">
                    Confidence
                  </p>
                  <p className="mt-1 font-mono text-sm font-semibold text-slate-700 dark:text-slate-200">
                    {Math.round(sessionConfidence * 100)}%
                  </p>
                </div>

                <div className="h-8 w-px bg-slate-200 dark:bg-slate-700" />

                <div>
                  <p className="text-[10px] font-bold uppercase tracking-wider text-slate-400 dark:text-slate-500">
                    Completeness
                  </p>
                  <p className="mt-1 font-mono text-xs font-semibold text-slate-700 dark:text-slate-200">
                    {session.security?.capture_completeness || 'COMPLETE'}
                  </p>
                </div>
              </div>

            </div>

            {/* PARTIAL CAPTURE WARNING BANNER */}
            {isPartial && (
              <div className="mt-5 flex items-start gap-3 rounded-xl border border-amber-200 dark:border-amber-800/60 bg-amber-50/80 dark:bg-amber-950/50 p-4 text-amber-800 dark:text-amber-300">
                <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-600 dark:text-amber-400" />
                <div className="text-xs leading-relaxed">
                  <span className="font-bold">Completeness: PARTIAL</span> — The packet capture does not contain the complete session stream. Some cryptographic or protocol properties cannot be fully proven from the available frames. Missing evidence is not converted into a false negative verdict.
                </div>
              </div>
            )}

            {downloadError && (
              <div className="mt-4 rounded-xl border border-red-200 dark:border-red-800/60 bg-red-50 dark:bg-red-950/50 p-3 text-xs text-red-700 dark:text-red-300">
                {downloadError}
              </div>
            )}
          </div>
        </div>

        {/* =========================================================
            SECTION JUMP NAVIGATION BAR (STICKY)
        ========================================================== */}
        <nav
          aria-label="Session sections navigation"
          className="sticky top-3 z-30 flex flex-wrap items-center justify-between gap-2 rounded-2xl border border-slate-200/90 dark:border-slate-800 bg-white/95 dark:bg-slate-900/95 p-1.5 shadow-sm dark:shadow-soft-dark backdrop-blur-md transition-all"
        >
          <div className="flex flex-wrap items-center gap-1.5 sm:gap-2">
            <button
              type="button"
              onClick={() => scrollToSection('section-forensics')}
              className={`inline-flex items-center gap-2 rounded-xl px-3.5 py-2 text-xs font-semibold transition-all ${
                activeSection === 'section-forensics'
                  ? 'bg-brand-600 text-white shadow-sm ring-2 ring-brand-600/20'
                  : 'bg-transparent text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800 hover:text-slate-900 dark:hover:text-slate-100'
              }`}
            >
              <Network className="h-3.5 w-3.5" />
              <span>Session Forensics</span>
            </button>

            <button
              type="button"
              onClick={() => scrollToSection('section-standards')}
              className={`inline-flex items-center gap-2 rounded-xl px-3.5 py-2 text-xs font-semibold transition-all ${
                activeSection === 'section-standards'
                  ? 'bg-brand-600 text-white shadow-sm ring-2 ring-brand-600/20'
                  : 'bg-transparent text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800 hover:text-slate-900 dark:hover:text-slate-100'
              }`}
            >
              <Layers className="h-3.5 w-3.5" />
              <span>Standards Context & Comparison</span>
            </button>

            <button
              type="button"
              onClick={() => scrollToSection('section-findings')}
              className={`inline-flex items-center gap-2 rounded-xl px-3.5 py-2 text-xs font-semibold transition-all ${
                activeSection === 'section-findings'
                  ? 'bg-brand-600 text-white shadow-sm ring-2 ring-brand-600/20'
                  : 'bg-transparent text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800 hover:text-slate-900 dark:hover:text-slate-100'
              }`}
            >
              <FileCode className="h-3.5 w-3.5" />
              <span>Session Findings</span>
              <span
                className={`ml-0.5 rounded-full px-1.5 py-0.5 font-mono text-[10px] font-bold ${
                  activeSection === 'section-findings'
                    ? 'bg-white/25 text-white'
                    : sessionFindings.length > 0
                    ? 'bg-amber-100 dark:bg-amber-950/60 text-amber-800 dark:text-amber-300'
                    : 'bg-emerald-100 dark:bg-emerald-950/60 text-emerald-800 dark:text-emerald-300'
                }`}
              >
                {sessionFindings.length}
              </span>
            </button>
          </div>
        </nav>

        {/* =========================================================
            SECTION 1: SESSION FORENSICS & TELEMETRY
        ========================================================== */}
        <section id="section-forensics" className="space-y-4 scroll-mt-24 pt-2">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between border-b-2 border-slate-200/80 dark:border-slate-800 pb-4 pt-2 gap-3">
            <div className="flex items-center gap-3.5">
              <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl bg-brand-50 dark:bg-brand-950/60 border border-brand-200/80 dark:border-brand-800 text-brand-600 dark:text-brand-400 shadow-sm">
                <Network className="h-5 w-5" />
              </div>
              <div>
                <h2 className="text-lg sm:text-xl font-bold tracking-tight text-slate-900 dark:text-white">
                  Session Forensics & Network Telemetry
                </h2>
                <p className="mt-0.5 text-xs sm:text-sm text-slate-500 dark:text-slate-400">
                  Traffic endpoints, protocol handshake negotiation, cryptographic parameters, and Wireshark trace
                </p>
              </div>
            </div>
          </div>

          {/* =========================================================
              FORENSIC EVIDENCE & WIRESHARK CARD
          ========================================================== */}
          <div className="rounded-2xl border border-slate-200/90 dark:border-slate-800 bg-white dark:bg-slate-900 p-6 shadow-sm dark:shadow-soft-dark space-y-4">
          <SectionHeader
            icon={Terminal}
            title="Forensic Evidence & Wireshark Filter"
            description="Traceable network evidence verifiable directly in Wireshark or tshark"
            color="sky"
          />

          <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-800/50 p-4 sm:p-5">
            <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
              <div className="space-y-1.5">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                    Wireshark Display Filter:
                  </span>
                  <span className="font-mono text-xs font-bold text-brand-700 dark:text-brand-300 bg-brand-50 dark:bg-brand-950/70 px-2.5 py-1 rounded border border-brand-200 dark:border-brand-800 select-all">
                    {wiresharkFilter || 'N/A'}
                  </span>
                </div>
                <p className="text-xs text-slate-500 dark:text-slate-400">
                  TCP Stream Index:{' '}
                  <span className="font-mono font-semibold text-slate-800 dark:text-slate-200">
                    {session.tcp_stream !== null && session.tcp_stream !== undefined
                      ? `#${session.tcp_stream}`
                      : 'None'}
                  </span>
                  {session.packet_count ? ` · ${session.packet_count} packets in this stream` : ''}
                </p>
              </div>

              <div className="flex flex-wrap items-center gap-2">
                {wiresharkFilter && (
                  <button
                    type="button"
                    onClick={handleCopyFilter}
                    className="inline-flex items-center gap-1.5 rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 px-3 py-2 text-xs font-semibold text-slate-700 dark:text-slate-200 shadow-sm transition hover:bg-slate-50 dark:hover:bg-slate-700 hover:border-slate-300 dark:hover:border-slate-600"
                    title="Copy Wireshark filter"
                  >
                    {copiedFilter ? (
                      <>
                        <Check className="h-3.5 w-3.5 text-emerald-600 dark:text-emerald-400" />
                        <span className="text-emerald-700 dark:text-emerald-400 font-bold">Copied!</span>
                      </>
                    ) : (
                      <>
                        <Copy className="h-3.5 w-3.5 text-slate-500 dark:text-slate-400" />
                        <span>Copy Filter</span>
                      </>
                    )}
                  </button>
                )}

                {analysisId && (
                  <button
                    type="button"
                    onClick={handleDownloadPcap}
                    disabled={isDownloading}
                    className="inline-flex items-center gap-1.5 rounded-xl border border-brand-600 bg-brand-600 px-3.5 py-2 text-xs font-semibold text-white shadow-sm transition hover:bg-brand-700 disabled:opacity-50"
                  >
                    <Download className="h-3.5 w-3.5" />
                    <span>{isDownloading ? 'Extracting...' : 'Download Stream PCAP'}</span>
                  </button>
                )}
              </div>
            </div>
          </div>
        </div>

        {/* =========================================================
            CONNECTION ENDPOINTS
        ========================================================== */}
        <div className="rounded-2xl border border-slate-200/90 dark:border-slate-800 bg-white dark:bg-slate-900 p-6 shadow-sm dark:shadow-soft-dark space-y-4">
          <SectionHeader
            icon={Shield}
            title="Connection Endpoints"
            description="Reconstructed communication endpoints and directional traffic flow"
            color="brand"
          />

          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            {/* CLIENT */}
            <div className="group relative rounded-xl border border-slate-200 dark:border-slate-800 bg-gradient-to-br from-brand-50/50 via-white to-white dark:from-brand-950/30 dark:via-slate-850 dark:to-slate-900 p-4 transition hover:border-brand-300 dark:hover:border-brand-700">
              <div className="flex items-center justify-between">
                <p className="text-[10px] font-bold uppercase tracking-wider text-slate-400 dark:text-slate-500">
                  Client · Source
                </p>
                <button
                  type="button"
                  onClick={handleCopyClient}
                  className="text-slate-400 dark:text-slate-500 hover:text-slate-600 dark:hover:text-slate-300 transition"
                  title="Copy client address"
                >
                  {copiedClient ? (
                    <Check className="h-3.5 w-3.5 text-emerald-600 dark:text-emerald-400" />
                  ) : (
                    <Copy className="h-3.5 w-3.5" />
                  )}
                </button>
              </div>

              <p className="mt-2 font-mono text-base font-bold text-slate-800 dark:text-slate-100">
                {session.client_ip || '—'}
                <span className="mx-1 text-slate-400 font-normal">:</span>
                <span className="text-brand-600 dark:text-brand-400">{session.client_port || '—'}</span>
              </p>
            </div>

            {/* SERVER */}
            <div className="group relative rounded-xl border border-slate-200 dark:border-slate-800 bg-gradient-to-br from-sky-50/50 via-white to-white dark:from-sky-950/30 dark:via-slate-850 dark:to-slate-900 p-4 transition hover:border-sky-300 dark:hover:border-sky-700">
              <div className="flex items-center justify-between">
                <p className="text-[10px] font-bold uppercase tracking-wider text-slate-400 dark:text-slate-500">
                  Server · Destination
                </p>
                <button
                  type="button"
                  onClick={handleCopyServer}
                  className="text-slate-400 dark:text-slate-500 hover:text-slate-600 dark:hover:text-slate-300 transition"
                  title="Copy server address"
                >
                  {copiedServer ? (
                    <Check className="h-3.5 w-3.5 text-emerald-600 dark:text-emerald-400" />
                  ) : (
                    <Copy className="h-3.5 w-3.5" />
                  )}
                </button>
              </div>

              <p className="mt-2 font-mono text-base font-bold text-slate-800 dark:text-slate-100">
                {session.server_ip || '—'}
                <span className="mx-1 text-slate-400 font-normal">:</span>
                <span className="text-sky-600 dark:text-sky-400">{session.server_port || '—'}</span>
              </p>
            </div>
          </div>
        </div>

        {/* =========================================================
            PROTOCOL HANDSHAKE & SECURITY CONTROLS
        ========================================================== */}
        <div className="rounded-2xl border border-slate-200/90 dark:border-slate-800 bg-white dark:bg-slate-900 p-6 shadow-sm dark:shadow-soft-dark space-y-4">
          <SectionHeader
            icon={Lock}
            title="Protocol Handshake"
            description="STARTTLS upgrade negotiation and authentication security controls"
            color="brand"
          />

          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <ControlCard
              title="Upgrade Advertised"
              description="STARTTLS or STLS capability was announced in server greeting/capabilities"
              value={session.security?.upgrade_advertised}
            />

            <ControlCard
              title="Upgrade Requested"
              description="Client initiated a STARTTLS command before payload or credentials"
              value={session.security?.upgrade_requested}
            />

            <ControlCard
              title="Upgrade Succeeded"
              description="Secure TLS layer was established after command acknowledgement"
              value={session.security?.upgrade_succeeded}
            />

            <ControlCard
              title="Auth Before TLS"
              description="Authentication credentials observed over plaintext channel"
              value={session.security?.authentication_before_tls}
              vulnerable
            />
          </div>
        </div>

        {/* =========================================================
            TLS PARAMETERS
        ========================================================== */}
        <div className="rounded-2xl border border-slate-200/90 dark:border-slate-800 bg-white dark:bg-slate-900 p-6 shadow-sm dark:shadow-soft-dark space-y-4">
          <SectionHeader
            icon={Key}
            title="TLS Parameters"
            description="Negotiated cryptographic cipher suite and forward secrecy parameters"
            color="sky"
          />

          {session.tls ? (
            <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-gradient-to-br from-sky-50/20 via-white to-white dark:from-sky-950/20 dark:via-slate-850 dark:to-slate-900 p-5">
              <div className="grid grid-cols-1 gap-6 sm:grid-cols-3">
                <div>
                  <p className="text-[10px] font-bold uppercase tracking-wider text-slate-400 dark:text-slate-500">
                    TLS Version
                  </p>
                  <p className="mt-1 font-mono text-sm font-bold text-slate-800 dark:text-slate-100">
                    {session.tls.version || 'UNKNOWN'}
                  </p>
                </div>

                <div>
                  <p className="text-[10px] font-bold uppercase tracking-wider text-slate-400 dark:text-slate-500">
                    Forward Secrecy (PFS)
                  </p>
                  <div className="mt-1 flex items-center gap-1.5">
                    {session.tls.pfs === 'YES' ? (
                      <CheckCircle2 className="h-4 w-4 text-emerald-500" />
                    ) : (
                      <HelpCircle className="h-4 w-4 text-slate-400" />
                    )}
                    <span
                      className={`font-mono text-sm font-bold ${
                        session.tls.pfs === 'YES'
                          ? 'text-emerald-700 dark:text-emerald-400'
                          : 'text-slate-600 dark:text-slate-400'
                      }`}
                    >
                      {session.tls.pfs || 'UNKNOWN'}
                    </span>
                  </div>
                </div>

                <div className="sm:col-span-3">
                  <p className="text-[10px] font-bold uppercase tracking-wider text-slate-400 dark:text-slate-500">
                    Negotiated Cipher Suite
                  </p>
                  <p className="mt-1 break-all font-mono text-xs font-semibold leading-relaxed text-slate-700 dark:text-slate-200 bg-slate-50 dark:bg-slate-800/80 p-2.5 rounded-lg border border-slate-200 dark:border-slate-700">
                    {session.tls.cipher_suite || 'None / Not Negotiated'}
                  </p>
                </div>
              </div>
            </div>
          ) : (
            <div className="rounded-xl border border-dashed border-slate-200 dark:border-slate-800 bg-white/60 dark:bg-slate-900/60 px-4 py-6 text-center text-xs text-slate-500 dark:text-slate-400">
              No TLS cryptographic parameters were negotiated for this session (Plaintext transmission).
            </div>
          )}
        </div>

        {/* =========================================================
            CERTIFICATE INFORMATION
        ========================================================== */}
        <div className="rounded-2xl border border-slate-200/90 dark:border-slate-800 bg-white dark:bg-slate-900 p-6 shadow-sm dark:shadow-soft-dark space-y-4">
          <SectionHeader
            icon={Award}
            title="Certificate Information"
            description="Observed X.509 server certificate details and PKI validation"
            color="purple"
          />

          {session.certificate?.visibility === 'NOT_OBSERVABLE' ? (
            <div className="flex items-start gap-3 rounded-xl border border-violet-200 dark:border-violet-800/60 bg-violet-50/70 dark:bg-violet-950/50 p-4 text-violet-800 dark:text-violet-300">
              <EyeOff className="mt-0.5 h-4 w-4 shrink-0 text-violet-600 dark:text-violet-400" />
              <div className="text-xs leading-relaxed">
                <span className="font-bold">Certificate Not Observable</span> — The certificate payload could not be inspected because TLS 1.3 encrypted the handshake or the packet capture commenced after certificate transmission.
              </div>
            </div>
          ) : session.certificate?.subject ? (
            <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-850 p-5 space-y-4">
              <div>
                <p className="text-[10px] font-bold uppercase tracking-wider text-slate-400 dark:text-slate-500">
                  Subject
                </p>
                <p className="mt-1 break-all font-mono text-xs font-semibold text-slate-800 dark:text-slate-100">
                  {session.certificate.subject}
                </p>
              </div>

              <div>
                <p className="text-[10px] font-bold uppercase tracking-wider text-slate-400 dark:text-slate-500">
                  Issuer
                </p>
                <p className="mt-1 break-all font-mono text-xs font-semibold text-slate-600 dark:text-slate-300">
                  {session.certificate.issuer || 'UNKNOWN'}
                </p>
              </div>

              <div className="grid grid-cols-2 gap-4 border-t border-slate-100 dark:border-slate-800 pt-4 sm:grid-cols-4">
                <div>
                  <p className="text-[10px] font-bold uppercase tracking-wider text-slate-400 dark:text-slate-500">
                    Valid From
                  </p>
                  <p className="mt-1 text-xs font-semibold text-slate-700 dark:text-slate-200">
                    {formatDate(session.certificate.valid_from)}
                  </p>
                </div>

                <div>
                  <p className="text-[10px] font-bold uppercase tracking-wider text-slate-400 dark:text-slate-500">
                    Valid Until
                  </p>
                  <p className="mt-1 text-xs font-semibold text-slate-700 dark:text-slate-200">
                    {formatDate(session.certificate.valid_until)}
                  </p>
                </div>

                <div>
                  <p className="text-[10px] font-bold uppercase tracking-wider text-slate-400 dark:text-slate-500">
                    Key Algorithm
                  </p>
                  <p className="mt-1 text-xs font-semibold text-slate-700 dark:text-slate-200">
                    {session.certificate.key_type || '—'}
                    {session.certificate.key_size ? ` (${session.certificate.key_size} bit)` : ''}
                  </p>
                </div>

                <div>
                  <p className="text-[10px] font-bold uppercase tracking-wider text-slate-400 dark:text-slate-500">
                    Self-Signed
                  </p>
                  <p
                    className={`mt-1 text-xs font-bold ${
                      session.certificate.self_signed ? 'text-amber-600 dark:text-amber-400' : 'text-slate-700 dark:text-slate-200'
                    }`}
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
          ) : (
            <div className="rounded-xl border border-dashed border-slate-200 dark:border-slate-800 bg-white/60 dark:bg-slate-900/60 px-4 py-6 text-center text-xs text-slate-500 dark:text-slate-400">
              No certificate payload was captured for this session.
            </div>
          )}
        </div>
        </section>

        {/* =========================================================
            SECTION 2: STANDARDS CONTEXT & BASELINE COMPARISON
        ========================================================== */}
        <section id="section-standards" className="space-y-4 scroll-mt-24 pt-6">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between border-b-2 border-slate-200/80 dark:border-slate-800 pb-4 gap-3">
            <div className="flex items-center gap-3.5">
              <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl bg-sky-50 dark:bg-sky-950/60 border border-sky-200/80 dark:border-sky-800 text-sky-600 dark:text-sky-400 shadow-sm">
                <Layers className="h-5 w-5" />
              </div>
              <div>
                <h2 className="text-lg sm:text-xl font-bold tracking-tight text-slate-900 dark:text-white">
                  Standards Context & Baseline Comparison
                </h2>
                <p className="mt-0.5 text-xs sm:text-sm text-slate-500 dark:text-slate-400">
                  Automated compliance verification against RFC standards and NIST/BSI security baseline criteria
                </p>
              </div>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <span className="hidden sm:inline-flex items-center gap-1.5 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900 px-2.5 py-1 text-xs text-slate-500 dark:text-slate-400">
                <Info className="h-3.5 w-3.5 text-brand-500 shrink-0" />
                <span>Contextual guidance · Separate from risk scoring</span>
              </span>
              <span className="hidden sm:inline-flex items-center gap-1.5 rounded-lg border border-sky-200 dark:border-sky-800 bg-sky-50 dark:bg-sky-950/60 px-2.5 py-1 font-mono text-xs font-semibold text-sky-700 dark:text-sky-300">
                <Layers className="h-3.5 w-3.5 text-sky-600 dark:text-sky-400" />
                RFC Standards
              </span>
            </div>
          </div>

          <div className="rounded-2xl border border-slate-200/90 dark:border-slate-800 bg-white dark:bg-slate-900 p-6 shadow-sm dark:shadow-soft-dark">
            <StandardsContextSection
              standardsContext={session.standards_context}
              session={session}
              hideHeader
            />
          </div>
        </section>

        {/* =========================================================
            SECTION 3: SESSION SECURITY FINDINGS
        ========================================================== */}
        <section id="section-findings" className="space-y-4 scroll-mt-24 pt-6">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between border-b-2 border-slate-200/80 dark:border-slate-800 pb-4 gap-3">
            <div className="flex items-center gap-3.5">
              <div
                className={`flex h-11 w-11 shrink-0 items-center justify-center rounded-xl border shadow-sm ${
                  sessionFindings.length > 0
                    ? 'bg-amber-50 dark:bg-amber-950/60 border-amber-200/80 dark:border-amber-800 text-amber-600 dark:text-amber-400'
                    : 'bg-emerald-50 dark:bg-emerald-950/60 border-emerald-200/80 dark:border-emerald-800 text-emerald-600 dark:text-emerald-400'
                }`}
              >
                <FileCode className="h-5 w-5" />
              </div>
              <div>
                <h2 className="text-lg sm:text-xl font-bold tracking-tight text-slate-900 dark:text-white">
                  Session Security Findings
                </h2>
                <p className="mt-0.5 text-xs sm:text-sm text-slate-500 dark:text-slate-400">
                  Independently verifiable security findings mapped to this session's packet stream
                </p>
              </div>
            </div>
            <span
              className={`inline-flex items-center gap-1.5 rounded-lg px-3 py-1 font-mono text-xs font-bold border shadow-sm ${
                sessionFindings.length > 0
                  ? 'bg-amber-50 dark:bg-amber-950/60 text-amber-800 dark:text-amber-300 border-amber-200 dark:border-amber-800'
                  : 'bg-emerald-50 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-300 border-emerald-200 dark:border-emerald-800'
              }`}
            >
              {sessionFindings.length > 0 ? (
                <>
                  <AlertTriangle className="h-3.5 w-3.5 text-amber-600 dark:text-amber-400" />
                  <span>{sessionFindings.length} {sessionFindings.length === 1 ? 'Finding' : 'Findings'}</span>
                </>
              ) : (
                <>
                  <CheckCircle2 className="h-3.5 w-3.5 text-emerald-600 dark:text-emerald-400" />
                  <span>0 Findings · Secure</span>
                </>
              )}
            </span>
          </div>

          <div className="rounded-2xl border border-slate-200/90 dark:border-slate-800 bg-white dark:bg-slate-900 p-6 shadow-sm dark:shadow-soft-dark">
          {sessionFindings.length > 0 ? (
            <div className="space-y-3">
              {sessionFindings.map((finding) => (
                <div
                  key={finding.finding_id || finding.id}
                  className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-850 p-4 shadow-sm space-y-2.5 transition hover:border-slate-300 dark:hover:border-slate-700"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <span
                        className={`inline-flex rounded-md border px-2 py-0.5 font-mono text-[10px] font-bold ${
                          finding.severity === 'CRITICAL'
                            ? 'border-red-200 dark:border-red-800 bg-red-50 dark:bg-red-950/60 text-red-700 dark:text-red-300'
                            : finding.severity === 'HIGH'
                            ? 'border-orange-200 dark:border-orange-800 bg-orange-50 dark:bg-orange-950/60 text-orange-700 dark:text-orange-300'
                            : finding.severity === 'MEDIUM'
                            ? 'border-amber-200 dark:border-amber-800 bg-amber-50 dark:bg-amber-950/60 text-amber-700 dark:text-amber-300'
                            : 'border-blue-200 dark:border-blue-800 bg-blue-50 dark:bg-blue-950/60 text-blue-700 dark:text-blue-300'
                        }`}
                      >
                        {finding.severity}
                      </span>
                      <h5 className="text-xs font-bold text-slate-800 dark:text-slate-100">
                        {finding.title}
                      </h5>
                    </div>
                    <span className="font-mono text-[10px] text-slate-400 dark:text-slate-500">
                      Confidence: {finding.confidence || 'OBSERVED'}
                    </span>
                  </div>

                  <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
                    {finding.description}
                  </p>

                  {finding.evidence && (
                    <div className="mt-2 rounded-lg bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 p-3">
                      <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400 mb-1.5">
                        Packet Evidence Trace:
                      </p>
                      <pre className="font-mono text-[11px] text-slate-700 dark:text-slate-300 whitespace-pre-wrap overflow-x-auto leading-relaxed">
                        {JSON.stringify(finding.evidence, null, 2)}
                      </pre>
                    </div>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-900/50 p-6 text-center text-xs text-slate-500 dark:text-slate-400">
              <ShieldCheck className="h-8 w-8 text-emerald-500 mx-auto mb-2" />
              <p className="font-semibold text-slate-700 dark:text-slate-200">No security findings or policy violations detected</p>
              <p className="mt-0.5 text-slate-500 dark:text-slate-400">This session satisfied all baseline protocol and TLS criteria.</p>
            </div>
          )}
        </div>
        </section>

        {/* =========================================================
            BOTTOM SESSION SWITCHER BAR
        ========================================================== */}
        <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 px-6 py-4 shadow-sm dark:shadow-soft-dark">
          <div className="flex items-center gap-2">
            <button
              type="button"
              disabled={!prevSession}
              onClick={() => handleSwitchSession(prevSession)}
              className="inline-flex items-center gap-1.5 rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 px-3.5 py-2 text-xs font-semibold text-slate-700 dark:text-slate-200 shadow-sm transition hover:bg-slate-50 dark:hover:bg-slate-700 disabled:opacity-40 disabled:pointer-events-none"
              title={prevSession ? `Previous session (${prevSession.session_id})` : undefined}
            >
              <ChevronLeft className="h-4 w-4" />
              <span>Previous</span>
            </button>

            <button
              type="button"
              disabled={!nextSession}
              onClick={() => handleSwitchSession(nextSession)}
              className="inline-flex items-center gap-1.5 rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 px-3.5 py-2 text-xs font-semibold text-slate-700 dark:text-slate-200 shadow-sm transition hover:bg-slate-50 dark:hover:bg-slate-700 disabled:opacity-40 disabled:pointer-events-none"
              title={nextSession ? `Next session (${nextSession.session_id})` : undefined}
            >
              <span>Next</span>
              <ChevronRight className="h-4 w-4" />
            </button>
          </div>

          <div className="text-center font-mono text-xs font-medium text-slate-500 dark:text-slate-400">
            {allSessions.length > 0 && currentIndex >= 0 ? (
              <span>Session {currentIndex + 1} of {allSessions.length}</span>
            ) : null}
          </div>

          <div>
            <Link
              to={`/analysis/${analysisId}?tab=sessions`}
              state={{ analysis }}
              className="inline-flex items-center gap-1.5 text-xs font-semibold text-brand-600 dark:text-brand-400 hover:text-brand-700 dark:hover:text-brand-300 transition"
            >
              <ArrowLeft className="h-3.5 w-3.5" />
              <span>Back to Session Table</span>
            </Link>
          </div>
        </div>

      </div>
    </div>
  );
}

/* ===============================================================
   SECTION HEADER HELPER COMPONENT
=============================================================== */
function SectionHeader({
  icon: Icon,
  title,
  description,
  color = 'brand',
}) {
  const colorStyles = {
    brand: 'bg-brand-500/10 border-brand-500/20 text-brand-600 dark:text-brand-400',
    sky: 'bg-sky-50 dark:bg-sky-950/60 border-sky-200 dark:border-sky-800 text-sky-600 dark:text-sky-400',
    purple: 'bg-violet-50 dark:bg-violet-950/60 border-violet-200 dark:border-violet-800 text-violet-600 dark:text-violet-400',
  };

  return (
    <div className="flex items-center gap-3">
      <div
        className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-xl border ${colorStyles[color]}`}
      >
        <Icon className="h-4 w-4" />
      </div>

      <div>
        <h4 className="text-sm font-semibold text-slate-800 dark:text-slate-100">{title}</h4>
        {description && (
          <p className="mt-0.5 text-[11px] text-slate-500 dark:text-slate-400">{description}</p>
        )}
      </div>
    </div>
  );
}

/* ===============================================================
   CONTROL CARD HELPER COMPONENT
=============================================================== */
function ControlCard({
  title,
  description,
  value,
  vulnerable = false,
}) {
  return (
    <div className="rounded-xl border border-slate-200/90 dark:border-slate-800 bg-white dark:bg-slate-850 px-4 py-3.5 shadow-[0_1px_2px_rgba(15,23,42,0.025)] transition hover:border-slate-300 dark:hover:border-slate-700">
      <div className="flex items-center justify-between gap-3">
        <div className="min-w-0">
          <p className="text-xs font-semibold text-slate-700 dark:text-slate-200">{title}</p>
          <p className="mt-0.5 text-[10px] leading-4 text-slate-400 dark:text-slate-500 line-clamp-2">{description}</p>
        </div>

        <div className="shrink-0">
          <TriStateBadge value={value} vulnerable={vulnerable} />
        </div>
      </div>
    </div>
  );
}

/* ===============================================================
   TRI-STATE BADGE HELPER COMPONENT
=============================================================== */
function TriStateBadge({ value, vulnerable = false }) {
  const state = formatTriState(value);
  const isYes = state.text === 'YES';
  const isNo = state.text === 'NO';

  let styles = 'border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 text-slate-600 dark:text-slate-400';

  if (vulnerable && isYes) {
    styles = 'border-red-200 dark:border-red-800/70 bg-red-50 dark:bg-red-950/60 text-red-700 dark:text-red-300 font-bold';
  } else if (isYes) {
    styles = 'border-emerald-200 dark:border-emerald-800/70 bg-emerald-50 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-300 font-bold';
  } else if (isNo) {
    styles = 'border-slate-200 dark:border-slate-700 bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-400';
  } else {
    styles = 'border-amber-200 dark:border-amber-800/70 bg-amber-50 dark:bg-amber-950/60 text-amber-700 dark:text-amber-300';
  }

  return (
    <span
      className={`inline-flex items-center rounded-lg border px-2 py-0.5 text-[11px] font-semibold font-mono tracking-wide ${styles}`}
    >
      {state.text}
    </span>
  );
}
