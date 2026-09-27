import React, {
  useEffect,
  useMemo,
  useState,
} from 'react';

import {
  Link,
  useParams,
} from 'react-router-dom';

import {
  ArrowLeft,
  Download,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Activity,
  Lock,
  AlertTriangle,
  Server,
  FileSearch,
  ClipboardList,
  CheckCircle2,
  ChevronRight,
  Wifi,
  Eye,
  Database,
  X,
  ArrowUpRight,
  FileWarning,
  Sparkles,
} from 'lucide-react';

import { useAnalysis } from '../hooks/useAnalysis';

import SessionTable from '../components/SessionTable';
import FindingsList from '../components/FindingsList';
import Recommendations, { getAffectedSessions } from '../components/Recommendations';
import CopilotChat from '../components/CopilotChat';
import LoadingState from '../components/LoadingState';
import ErrorState from '../components/ErrorState';


export default function Analysis() {

  const { id } = useParams();

  const {
    analysis,
    loading,
    error,
    fetchAnalysis,
    exportJson,
  } = useAnalysis(id);

  const [activeTab, setActiveTab] =
    useState('overview');

  const [selectedFinding, setSelectedFinding] =
    useState(null);

  const [isRefreshing, setIsRefreshing] =
    useState(false);

  const sessions = analysis?.sessions || [];
  /* ============================================================
     FETCH ANALYSIS
  ============================================================ */

  useEffect(() => {

    if (id) {
      fetchAnalysis(id);
    }

  }, [id, fetchAnalysis]);


  /* ============================================================
     REFRESH
  ============================================================ */

  const handleRefresh = async () => {

    if (isRefreshing) return;

    setIsRefreshing(true);

    try {

      await fetchAnalysis(id);

    } finally {

      setTimeout(() => {
        setIsRefreshing(false);
      }, 450);

    }

  };


  /* ============================================================
     ANALYSIS LANDING PAGE
  ============================================================ */

  if (!id) {

    return (

      <div className="
        mx-auto
        max-w-7xl
        px-4
        py-8
        sm:px-6
        lg:px-8
      ">

        {/* HEADER */}

        <div className="mb-8">

          <div className="flex items-center gap-3">

            <div className="
              flex h-11 w-11
              items-center justify-center
              rounded-xl
              border border-brand-200
              bg-brand-50
              shadow-sm
            ">

              <FileSearch className="
                h-5 w-5
                text-brand-600
              " />

            </div>


            <div>

              <p className="
                text-[10px]
                font-bold
                uppercase
                tracking-[0.16em]
                text-brand-600
              ">
                Security Analysis
              </p>


              <h1 className="
                mt-1
                text-2xl
                font-bold
                tracking-tight
                text-slate-900
              ">
                Analysis Workspace
              </h1>


              <p className="
                mt-1
                text-sm
                text-slate-500
              ">
                Open an analysis record to inspect sessions,
                security findings, and recommended actions.
              </p>

            </div>

          </div>

        </div>


        {/* EMPTY STATE */}

        <div className="
          rounded-2xl
          border border-slate-200
          bg-white
          p-8
          shadow-sm
          sm:p-12
        ">

          <div className="
            mx-auto
            max-w-lg
            text-center
          ">

            <div className="
              mx-auto
              flex h-14 w-14
              items-center justify-center
              rounded-2xl
              border border-brand-200
              bg-brand-50
            ">

              <Database className="
                h-6 w-6
                text-brand-600
              " />

            </div>


            <h2 className="
              mt-5
              text-lg
              font-semibold
              text-slate-900
            ">
              No analysis selected
            </h2>


            <p className="
              mt-2
              text-sm
              leading-6
              text-slate-500
            ">
              Upload a PCAP capture from the Dashboard
              or open a previously completed analysis.
            </p>


            <div className="
              mt-6
              flex flex-col
              justify-center
              gap-3
              sm:flex-row
            ">

              <Link
                to="/"
                className="
                  inline-flex
                  items-center
                  justify-center
                  gap-2
                  rounded-lg
                  bg-brand-600
                  px-4 py-2.5
                  text-sm
                  font-semibold
                  text-white
                  shadow-sm
                  transition-all
                  hover:bg-brand-700
                  hover:shadow-md
                "
              >

                <Activity className="h-4 w-4" />

                Go to Dashboard

              </Link>


              <Link
                to="/history"
                className="
                  inline-flex
                  items-center
                  justify-center
                  gap-2
                  rounded-lg
                  border border-slate-200
                  bg-white
                  px-4 py-2.5
                  text-sm
                  font-semibold
                  text-slate-700
                  transition-colors
                  hover:bg-slate-50
                "
              >

                <ClipboardList className="h-4 w-4" />

                View History

              </Link>

            </div>

          </div>

        </div>

      </div>

    );

  }

  /* ============================================================
     SESSION CALCULATIONS
  ============================================================ */

  const unsecuredSessions = useMemo(() => {

    return sessions.filter((session) => {

      const encryption = String(
        session?.encryption ||
        session?.encryption_method ||
        session?.security ||
        ''
      ).toLowerCase();


      const posture = String(
        session?.security_posture ||
        session?.status ||
        ''
      ).toLowerCase();


      return (

        encryption.includes('plain') ||
        encryption.includes('none') ||
        encryption.includes('unsecure') ||
        posture.includes('vulnerable')

      );

    }).length;

  }, [sessions]);


  const plaintextSessions = useMemo(() => {

    return sessions.filter((session) => {

      const encryption = String(
        session?.encryption ||
        session?.encryption_method ||
        ''
      ).toLowerCase();


      return encryption.includes('plain');

    }).length;

  }, [sessions]);


  /* ============================================================
     PROTOCOL COUNTS
  ============================================================ */

  const protocolCounts = useMemo(() => {

    const counts = {
      SMTP: 0,
      IMAP: 0,
      POP3: 0,
    };


    sessions.forEach((session) => {

      const protocol = String(
        session?.protocol || ''
      ).toUpperCase();


      if (protocol.includes('SMTP')) {
        counts.SMTP += 1;
      }


      if (protocol.includes('IMAP')) {
        counts.IMAP += 1;
      }


      if (protocol.includes('POP3')) {
        counts.POP3 += 1;
      }

    });


    return counts;

  }, [sessions]);


  /* ============================================================
     ENCRYPTION COUNTS
  ============================================================ */

  const encryptionCounts = useMemo(() => {

    const counts = {
      starttls: 0,
      implicitTls: 0,
      plaintext: 0,
    };


    sessions.forEach((session) => {

      const encryption = String(
        session?.encryption ||
        session?.encryption_method ||
        session?.security ||
        ''
      ).toLowerCase();


      if (
        encryption.includes('starttls')
      ) {

        counts.starttls += 1;

      } else if (

        encryption.includes('implicit') ||
        encryption.includes('tls')

      ) {

        counts.implicitTls += 1;

      } else if (

        encryption.includes('plain') ||
        encryption.includes('none')

      ) {

        counts.plaintext += 1;

      }

    });


    return counts;

  }, [sessions]);

  /* ============================================================
     LOADING
  ============================================================ */

  if (loading) {

    return (

      <div className="
        mx-auto
        max-w-7xl
        px-4
        py-16
        sm:px-6
        lg:px-8
      ">

        <LoadingState
          message="Retrieving analysis details..."
          subtext={`Fetching capture ID: ${id}`}
        />

      </div>

    );

  }


  /* ============================================================
     ERROR
  ============================================================ */

  if (error || !analysis) {

    return (

      <div className="
        mx-auto
        max-w-7xl
        space-y-5
        px-4
        py-10
        sm:px-6
        lg:px-8
      ">

        <Link
          to="/analysis"
          className="
            inline-flex
            items-center
            gap-2
            text-sm
            font-medium
            text-brand-600
            transition-colors
            hover:text-brand-700
          "
        >

          <ArrowLeft className="h-4 w-4" />

          Back to Analyses

        </Link>


        <ErrorState
          title="Analysis Record Unavailable"
          message={
            error ||
            'Could not find or retrieve analysis data for this capture.'
          }
          onRetry={() => fetchAnalysis(id)}
        />

      </div>

    );

  }


  /* ============================================================
     DATA
  ============================================================ */

  const riskLevel =
    analysis?.risk?.level ||
    analysis?.risk?.label ||
    'UNKNOWN';


  const riskScore =
    analysis?.risk?.score ?? 0;



  const findings =
    analysis?.findings || [];


  const recommendations =
    analysis?.recommendations || [];


  const summary =
    analysis?.summary || {};


  const totalSessions =
    summary?.total_sessions ??
    sessions.length ??
    0;


  const findingsCount =
    summary?.findings_count ??
    findings.length ??
    0;


  


  const topFindings =
    findings.slice(0, 3);


  const riskStyles =
    getRiskStyles(riskLevel);


  const formattedDate =
    analysis?.uploaded_at
      ? new Date(
          analysis.uploaded_at
        ).toLocaleString()
      : 'Not available';


  /* ============================================================
     MAIN PAGE
  ============================================================ */

  return (

    <div className="
      mx-auto
      max-w-7xl
      px-4
      py-7
      sm:px-6
      lg:px-8
    ">


      {/* ========================================================
          PAGE HEADER
      ======================================================== */}

      <div className="mb-7">

        <Link
          to="/analysis"
          className="
            mb-5
            inline-flex
            items-center
            gap-2
            text-xs
            font-semibold
            text-brand-600
            transition-colors
            hover:text-brand-700
          "
        >

          <ArrowLeft className="h-3.5 w-3.5" />

          Back to Analyses

        </Link>


        <div className="
          flex flex-col
          gap-5
          xl:flex-row
          xl:items-end
          xl:justify-between
        ">


          {/* TITLE */}

          <div>

            <div className="
              flex items-center
              gap-3
            ">

              <div className="
                flex h-11 w-11
                items-center justify-center
                rounded-xl
                border border-brand-100
                bg-brand-50
                shadow-sm
              ">

                <ShieldCheck className="
                  h-5 w-5
                  text-brand-600
                " />

              </div>


              <div>

                <div className="
                  flex items-center
                  gap-2
                ">

                  <p className="
                    text-[10px]
                    font-bold
                    uppercase
                    tracking-[0.16em]
                    text-brand-600
                  ">
                    Security Analysis
                  </p>


                  <span className="
                    rounded-full
                    bg-yellow-50
                    px-2 py-0.5
                    text-[9px]
                    font-semibold
                    text-yellow-700
                  ">
                    Completed
                  </span>

                </div>


                <h1 className="
                  mt-1
                  text-2xl
                  font-bold
                  tracking-tight
                  text-slate-900
                ">
                  Analysis Report
                </h1>

              </div>

            </div>


            <p className="
              mt-4
              max-w-2xl
              text-sm
              leading-6
              text-slate-500
            ">
              Review the captured email traffic, evaluate
              protocol security posture, investigate detected
              vulnerabilities, and apply recommended remediation
              actions.
            </p>

          </div>


          {/* ACTIONS */}

          <div className="
            flex flex-wrap
            items-center
            gap-2
          ">

            <button
              type="button"
              onClick={handleRefresh}
              disabled={isRefreshing}
              className="
                inline-flex
                items-center
                gap-2
                rounded-lg
                border border-slate-200
                bg-white
                px-4 py-2.5
                text-xs
                font-semibold
                text-slate-700
                shadow-sm
                transition-all
                hover:bg-slate-50
                hover:border-slate-300
                active:scale-[0.98]
                disabled:cursor-not-allowed
                disabled:opacity-70
              "
            >

              <RefreshCw
                className={`
                  h-3.5 w-3.5
                  ${
                    isRefreshing
                      ? 'animate-spin'
                      : ''
                  }
                `}
              />

              {isRefreshing
                ? 'Refreshing...'
                : 'Refresh'}

            </button>


            <button
              type="button"
              onClick={() =>
                exportJson(
                  analysis.analysis_id
                )
              }
              className="
                inline-flex
                items-center
                gap-2
                rounded-lg
                bg-brand-600
                px-4 py-2.5
                text-xs
                font-semibold
                text-white
                shadow-sm
                transition-all
                hover:bg-brand-700
                hover:shadow-md
                active:scale-[0.98]
              "
            >

              <Download className="h-3.5 w-3.5" />

              Export Report

            </button>

          </div>

        </div>

      </div>


      {/* ========================================================
          CAPTURE INFO
      ======================================================== */}

      <div className="
        mb-6
        rounded-xl
        border border-slate-200
        bg-white
        px-5 py-4
        shadow-sm
      ">

        <div className="
          flex flex-col
          gap-4
          lg:flex-row
          lg:items-center
          lg:justify-between
        ">

          <div className="min-w-0">

            <div className="
              flex items-center
              gap-2
            ">

              <div className="
                flex h-8 w-8
                items-center justify-center
                rounded-lg
                bg-brand-50
              ">

                <Database className="
                  h-4 w-4
                  text-brand-600
                " />

              </div>


              <div className="min-w-0">

                <h2 className="
                  truncate
                  text-sm
                  font-semibold
                  text-slate-900
                ">
                  {analysis.filename ||
                    'Captured Analysis'}
                </h2>


                <p className="
                  mt-0.5
                  text-[10px]
                  text-slate-400
                ">
                  Network capture security assessment
                </p>

              </div>

            </div>


            <div className="
              mt-3
              flex flex-wrap
              gap-x-5 gap-y-2
              text-[11px]
              text-slate-500
            ">

              <span>

                Analysis ID:{' '}

                <span className="
                  rounded
                  bg-slate-100
                  px-1.5 py-0.5
                  font-mono
                  text-slate-600
                ">
                  {analysis.analysis_id}
                </span>

              </span>


              <span>
                Uploaded: {formattedDate}
              </span>

            </div>

          </div>


          <div className="
            flex items-center
            gap-2
            rounded-full
            bg-yellow-50
            px-3 py-1.5
            self-start
            lg:self-auto
          ">

            <span className="
              h-2 w-2
              rounded-full
              bg-yellow-500
            " />

            <span className="
              text-xs
              font-semibold
              text-yellow-700
            ">
              Analysis completed
            </span>

          </div>

        </div>

      </div>


      {/* ========================================================
          RISK SUMMARY
      ======================================================== */}

      <div
        className="
          mb-6
          overflow-hidden
          rounded-2xl
          border
          shadow-sm
        "
        style={riskStyles.heroBorder}
      >

        <div
          className="
            flex flex-col
            gap-6
            p-5
            sm:p-6
            lg:flex-row
            lg:items-center
            lg:justify-between
          "
          style={riskStyles.heroGradient}
        >


          <div className="
            flex items-start
            gap-4
          ">

            <div
              className={`
                flex h-12 w-12
                shrink-0
                items-center justify-center
                rounded-xl
                ${riskStyles.iconBg}
              `}
            >

              <ShieldAlert
                className={`
                  h-5 w-5
                  ${riskStyles.iconText}
                `}
              />

            </div>


            <div>

              <div className="
                flex flex-wrap
                items-center
                gap-2
              ">

                <span
                  className={`
                    rounded-md
                    border
                    px-2 py-1
                    text-[10px]
                    font-bold
                    uppercase
                    tracking-wide
                    ${riskStyles.badge}
                  `}
                >
                  {riskLevel}
                </span>


                <span className="
                  text-[11px]
                  text-slate-400
                ">
                  Overall security posture
                </span>

              </div>


              <h2 className="
                mt-3
                text-lg
                font-semibold
                text-slate-900
              ">
                {getRiskTitle(riskLevel)}
              </h2>


              <p className="
                mt-1.5
                max-w-2xl
                text-sm
                leading-6
                text-slate-500
              ">
                {analysis?.risk?.description ||
                  analysis?.summary?.description ||
                  'Security weaknesses were detected in this capture and require review.'}
              </p>

            </div>

          </div>


          {/* SCORE */}

          <div className="
            flex
            shrink-0
            items-center
            gap-4
            rounded-xl
            border border-slate-200
            bg-slate-50
            px-4 py-3
          ">

            <RiskScoreRing
              score={riskScore}
              riskStyles={riskStyles}
            />

            <div>

              <p className="
                text-[10px]
                font-bold
                uppercase
                tracking-wide
                text-slate-400
              ">
                Risk Score
              </p>


              <p className="
                mt-1
                max-w-[160px]
                text-xs
                leading-5
                text-slate-600
              ">
                Higher scores indicate greater observed
                security risk.
              </p>

            </div>

          </div>

        </div>

      </div>


      {/* ========================================================
          METRICS
      ======================================================== */}

      <div className="
        mb-6
        grid grid-cols-2
        gap-3
        lg:grid-cols-4
      ">

        <MetricCard
          icon={<Server className="h-4 w-4" />}
          label="Total Sessions"
          value={totalSessions}
          iconClass="text-brand-600 bg-brand-50"
        />


        <MetricCard
          icon={<ShieldAlert className="h-4 w-4" />}
          label="Unsecured Sessions"
          value={unsecuredSessions}
          iconClass="text-rose-600 bg-rose-50"
        />


        <MetricCard
          icon={<AlertTriangle className="h-4 w-4" />}
          label="Security Findings"
          value={findingsCount}
          iconClass="text-amber-600 bg-amber-50"
        />


        <MetricCard
          icon={<Lock className="h-4 w-4" />}
          label="Plaintext Sessions"
          value={plaintextSessions}
          iconClass="text-orange-600 bg-orange-50"
        />

      </div>


      {/* ========================================================
          TABS
      ======================================================== */}

      <div className="mb-6">

        <div className="
          overflow-x-auto
          pb-1
        ">

          <div className="
            flex
            w-full
            items-center
            gap-1
            rounded-xl
            border border-slate-200
            bg-slate-100/80
            p-1.5
          ">

            <AnalysisTab
              active={activeTab === 'overview'}
              onClick={() =>
                setActiveTab('overview')
              }
              icon={<Activity className="h-3.5 w-3.5" />}
              label="Overview"
            />


            <AnalysisTab
              active={activeTab === 'sessions'}
              onClick={() =>
                setActiveTab('sessions')
              }
              icon={<Server className="h-3.5 w-3.5" />}
              label="Sessions"
              count={totalSessions}
            />


            <AnalysisTab
              active={activeTab === 'findings'}
              onClick={() =>
                setActiveTab('findings')
              }
              icon={<ShieldAlert className="h-3.5 w-3.5" />}
              label="Findings"
              count={findingsCount}
            />


            <AnalysisTab
              active={
                activeTab === 'recommendations'
              }
              onClick={() =>
                setActiveTab('recommendations')
              }
              icon={
                <CheckCircle2 className="h-3.5 w-3.5" />
              }
              label="Recommendations"
              count={recommendations.length}
            />

            <AnalysisTab
              active={
                activeTab === 'ai-assistance'
              }
              onClick={() =>
                setActiveTab('ai-assistance')
              }
              icon={
                <img
                  src="/Agent_SMS_logo_2.jpeg"
                  alt="Agent SMS"
                  className="h-4 w-4 rounded-sm object-contain"
                />
              }
              label="AI Assistance"
            />

          </div>

        </div>

      </div>


      {/* ========================================================
          OVERVIEW TAB
      ======================================================== */}

      {activeTab === 'overview' && (

        <div className="space-y-5">


          {/* PROTOCOL + ENCRYPTION */}

          <div className="
            grid gap-5
            lg:grid-cols-2
          ">

            <OverviewCard
              icon={<Wifi className="h-4 w-4" />}
              title="Protocol Coverage"
              subtitle="Email protocols detected in this capture"
              iconClass="text-brand-600 bg-brand-50"
            >

              <ProtocolRow
                protocol="SMTP"
                count={protocolCounts.SMTP}
                dot="bg-brand-500"
              />

              <ProtocolRow
                protocol="IMAP"
                count={protocolCounts.IMAP}
                dot="bg-sky-500"
              />

              <ProtocolRow
                protocol="POP3"
                count={protocolCounts.POP3}
                dot="bg-slate-400"
              />

            </OverviewCard>


            <OverviewCard
              icon={<Lock className="h-4 w-4" />}
              title="Transport Encryption"
              subtitle="Encryption methods observed"
              iconClass="text-yellow-600 bg-yellow-50"
            >

              <ProtocolRow
                protocol="STARTTLS"
                count={encryptionCounts.starttls}
                dot="bg-brand-500"
              />

              <ProtocolRow
                protocol="Implicit TLS"
                count={encryptionCounts.implicitTls}
                dot="bg-yellow-500"
              />

              <ProtocolRow
                protocol="Plaintext"
                count={encryptionCounts.plaintext}
                dot="bg-rose-500"
                danger
              />

            </OverviewCard>

          </div>


          {/* SECURITY HIGHLIGHTS */}

          <div className="
            overflow-hidden
            rounded-xl
            border border-slate-200
            bg-white
            shadow-sm
          ">

            <div className="
              flex flex-col
              gap-3
              border-b border-slate-100
              px-5 py-4
              sm:flex-row
              sm:items-center
              sm:justify-between
            ">

              <div>

                <div className="
                  flex items-center
                  gap-2
                ">

                  <div className="
                    flex h-8 w-8
                    items-center justify-center
                    rounded-lg
                    bg-amber-50
                  ">

                    <ShieldAlert className="
                      h-4 w-4
                      text-amber-600
                    " />

                  </div>


                  <div>

                    <h2 className="
                      text-sm
                      font-semibold
                      text-slate-900
                    ">
                      Security Highlights
                    </h2>


                    <p className="
                      mt-0.5
                      text-xs
                      text-slate-500
                    ">
                      Most important weaknesses identified
                      during analysis.
                    </p>

                  </div>

                </div>

              </div>


              {findings.length > 3 && (

                <button
                  type="button"
                  onClick={() =>
                    setActiveTab('findings')
                  }
                  className="
                    inline-flex
                    items-center
                    gap-1
                    text-xs
                    font-semibold
                    text-brand-600
                    hover:text-brand-700
                  "
                >

                  View all findings

                  <ChevronRight className="h-3.5 w-3.5" />

                </button>

              )}

            </div>


            <div className="
              divide-y
              divide-slate-100
            ">

              {topFindings.length > 0 ? (

                topFindings.map(
                  (finding, index) => (

                    <FindingHighlight
                      key={
                        finding.id ||
                        finding.finding_id ||
                        index
                      }
                      finding={finding}
                      onViewDetails={
                        setSelectedFinding
                      }
                    />

                  )
                )

              ) : (

                <div className="
                  p-10
                  text-center
                ">

                  <div className="
                    mx-auto
                    flex h-12 w-12
                    items-center justify-center
                    rounded-xl
                    bg-yellow-50
                  ">

                    <CheckCircle2 className="
                      h-6 w-6
                      text-yellow-500
                    " />

                  </div>


                  <p className="
                    mt-4
                    text-sm
                    font-semibold
                    text-slate-700
                  ">
                    No major findings detected
                  </p>


                  <p className="
                    mt-1
                    text-xs
                    text-slate-500
                  ">
                    No security weaknesses are currently
                    available for this analysis.
                  </p>

                </div>

              )}

            </div>

          </div>


          {/* RECOMMENDATIONS */}

          {recommendations.length > 0 && (

            <div className="
              overflow-hidden
              rounded-xl
              border border-slate-200
              bg-white
              shadow-sm
            ">

              <div className="
                flex items-center
                justify-between
                border-b border-slate-100
                px-5 py-4
              ">

                <div>

                  <div className="
                    flex items-center
                    gap-2
                  ">

                    <div className="
                      flex h-8 w-8
                      items-center justify-center
                      rounded-lg
                      bg-yellow-50
                    ">

                      <CheckCircle2 className="
                        h-4 w-4
                        text-yellow-600
                      " />

                    </div>


                    <div>

                      <h2 className="
                        text-sm
                        font-semibold
                        text-slate-900
                      ">
                        Recommended Actions
                      </h2>


                      <p className="
                        mt-0.5
                        text-xs
                        text-slate-500
                      ">
                        Prioritized remediation for detected
                        security issues.
                      </p>

                    </div>

                  </div>

                </div>


                <button
                  type="button"
                  onClick={() =>
                    setActiveTab(
                      'recommendations'
                    )
                  }
                  className="
                    text-xs
                    font-semibold
                    text-brand-600
                    hover:text-brand-700
                  "
                >
                  View all
                </button>

              </div>


              <div className="
                grid gap-3
                p-5
                lg:grid-cols-2
              ">

                {recommendations
                  .slice(0, 2)
                  .map(
                    (recommendation, index) => (

                      <RecommendationPreview
                        key={
                          recommendation.id ||
                          recommendation.rec_id ||
                          index
                        }
                        recommendation={
                          recommendation
                        }
                        findings={findings}
                        sessions={sessions}
                        onSelectSession={(sId) => setActiveTab('sessions')}
                      />

                    )
                  )}

              </div>

            </div>

          )}

        </div>

      )}


      {/* ========================================================
          SESSIONS TAB
      ======================================================== */}

      {activeTab === 'sessions' && (

        <div className="
          overflow-hidden
          rounded-xl
          border border-slate-200
          bg-white
          shadow-sm
        ">

          <div className="
            p-3
            sm:p-5
          ">

            <SessionTable
              sessions={sessions}
              findings={findings}
            />

          </div>

        </div>

      )}


      {/* ========================================================
          FINDINGS TAB
      ======================================================== */}

      {activeTab === 'findings' && (

        <div className="
          overflow-hidden
          rounded-xl
          border border-slate-200
          bg-white
          shadow-sm
        ">

          <div className="
            p-3
            sm:p-5
          ">

            <FindingsList
              findings={findings}
            />

          </div>

        </div>

      )}


      {/* ========================================================
          RECOMMENDATIONS TAB
      ======================================================== */}

      {activeTab === 'recommendations' && (

        <div className="
          overflow-hidden
          rounded-xl
          border border-slate-200
          bg-white
          shadow-sm
        ">

          <div className="
            p-3
            sm:p-5
          ">

            <Recommendations
              recommendations={recommendations}
              findings={findings}
              sessions={sessions}
              onSelectSession={(sId) => setActiveTab('sessions')}
            />

          </div>

        </div>

      )}


      {/* ========================================================
          AI ASSISTANCE TAB
      ======================================================== */}

      {activeTab === 'ai-assistance' && (
        <CopilotChat analysis={analysis} />
      )}


      {/* ========================================================
          FINDING DETAILS MODAL
      ======================================================== */}

      {selectedFinding && (

        <FindingDetailsModal
          finding={selectedFinding}
          onClose={() =>
            setSelectedFinding(null)
          }
        />

      )}

    </div>

  );

}


/* ===============================================================
   METRIC CARD
=============================================================== */

function MetricCard({
  icon,
  label,
  value,
  iconClass,
}) {

  return (

    <div className="
      group
      rounded-xl
      border border-slate-200
      bg-white
      p-4
      shadow-sm
      transition-all
      duration-200
      hover:-translate-y-0.5
      hover:shadow-md
    ">

      <div className="
        flex items-start
        justify-between
      ">

        <div>

          <p className="
            text-[10px]
            font-semibold
            uppercase
            tracking-[0.08em]
            text-slate-400
          ">
            {label}
          </p>


          <p className="
            mt-2
            text-2xl
            font-bold
            tracking-tight
            text-slate-900
          ">
            {value}
          </p>

        </div>


        <div
          className={`
            flex h-10 w-10
            items-center justify-center
            rounded-xl
            transition-transform
            group-hover:scale-105
            ${iconClass}
          `}
        >
          {icon}
        </div>

      </div>

    </div>

  );

}


/* ===============================================================
   ANALYSIS TAB
=============================================================== */

function AnalysisTab({
  active,
  onClick,
  icon,
  label,
  count,
}) {

  return (

    <button
      type="button"
      onClick={onClick}
      className={`
        flex 
        flex-1
        items-center
        justify-center
        gap-2
        rounded-lg
        px-4 py-2.5
        text-xs
        font-semibold
        transition-all
        duration-200

        ${
          active
            ? `
              bg-white
              text-brand-700
              shadow-sm
              ring-1
              ring-slate-200
            `
            : `
              text-slate-500
              hover:bg-white/70
              hover:text-slate-800
            `
        }
      `}
    >

      <span
        className={`
          flex h-6 w-6
          items-center justify-center
          rounded-md

          ${
            active
              ? `
                bg-brand-50
                text-brand-600
              `
              : `
                text-slate-400
              `
          }
        `}
      >
        {icon}
      </span>


      <span>
        {label}
      </span>


      {count !== undefined && (

        <span
          className={`
            min-w-[20px]
            rounded-full
            px-1.5 py-0.5
            text-center
            text-[9px]
            font-bold

            ${
              active
                ? `
                  bg-brand-50
                  text-brand-700
                `
                : `
                  bg-slate-200
                  text-slate-500
                `
            }
          `}
        >
          {count}
        </span>

      )}

    </button>

  );

}


/* ===============================================================
   OVERVIEW CARD
=============================================================== */

function OverviewCard({
  icon,
  title,
  subtitle,
  iconClass,
  children,
}) {

  return (

    <div className="
      overflow-hidden
      rounded-xl
      border border-slate-200
      bg-white
      shadow-sm
    ">

      <div className="
        flex items-center
        gap-3
        border-b border-slate-100
        px-5 py-4
      ">

        <div
          className={`
            flex h-9 w-9
            items-center justify-center
            rounded-lg
            ${iconClass}
          `}
        >
          {icon}
        </div>


        <div>

          <h2 className="
            text-sm
            font-semibold
            text-slate-900
          ">
            {title}
          </h2>


          <p className="
            mt-0.5
            text-[10px]
            text-slate-500
          ">
            {subtitle}
          </p>

        </div>

      </div>


      <div className="
        divide-y
        divide-slate-100
        px-5
      ">
        {children}
      </div>

    </div>

  );

}


/* ===============================================================
   PROTOCOL ROW
=============================================================== */

function ProtocolRow({
  protocol,
  count,
  dot,
  danger = false,
}) {

  return (

    <div className="
      flex items-center
      justify-between
      py-4
    ">

      <div className="
        flex items-center
        gap-3
      ">

        <span
          className={`
            h-2.5 w-2.5
            rounded-full
            ${dot}
          `}
        />


        <span
          className={`
            text-xs
            font-medium

            ${
              danger
                ? 'text-rose-700'
                : 'text-slate-700'
            }
          `}
        >
          {protocol}
        </span>

      </div>


      <span className="
        min-w-[30px]
        rounded-md
        bg-slate-50
        px-2 py-1
        text-center
        text-xs
        font-semibold
        text-slate-700
      ">
        {count}
      </span>

    </div>

  );

}


/* ===============================================================
   FINDING HIGHLIGHT
=============================================================== */

function FindingHighlight({
  finding,
  onViewDetails,
}) {

  const severity =
    finding?.severity ||
    finding?.level ||
    'INFO';


  const title =
    finding?.title ||
    finding?.name ||
    finding?.message ||
    'Security finding';


  const description =
    finding?.description ||
    finding?.detail ||
    'A protocol security weakness was observed in this session.';


  const severityStyle =
    getSeverityStyles(severity);


  return (

    <div className="
      group
      relative
      flex flex-col
      gap-3
      px-5 py-4
      transition-colors
      hover:bg-slate-50/60
      sm:flex-row
      sm:items-center
      sm:justify-between
    ">

      {/* left accent bar */}
      <span
        className={`
          absolute left-0 top-3 bottom-3
          w-[3px]
          rounded-full
          opacity-0
          transition-opacity
          group-hover:opacity-100
          ${severityStyle.accentBar}
        `}
      />

      <div className="
        flex items-start
        gap-3
      ">

        <div
          className={`
            mt-0.5
            flex h-8 w-8
            shrink-0
            items-center justify-center
            rounded-lg
            ${severityStyle.iconBg}
          `}
        >

          <AlertTriangle
            className={`
              h-3.5 w-3.5
              ${severityStyle.iconText}
            `}
          />

        </div>


        <div className="min-w-0">

          <div className="
            flex flex-wrap
            items-center
            gap-2
            mb-1.5
          ">

            <span
              className={`
                inline-flex items-center
                rounded-full
                px-2 py-0.5
                text-[9px]
                font-bold
                uppercase
                tracking-wide
                ${severityStyle.pill}
              `}
            >
              {severity}
            </span>

          </div>


          <h3 className="
            text-sm
            font-semibold
            text-slate-800
            leading-snug
          ">
            {title}
          </h3>


          <p className="
            mt-1
            text-xs
            leading-5
            text-slate-500
            line-clamp-2
          ">
            {description}
          </p>

        </div>

      </div>


      <button
        type="button"
        onClick={() =>
          onViewDetails(finding)
        }
        className="
          inline-flex
          shrink-0
          items-center
          gap-1.5
          self-start
          rounded-lg
          border border-slate-200
          bg-white
          px-3 py-1.5
          text-[11px]
          font-semibold
          text-slate-600
          shadow-sm
          transition-all
          hover:border-brand-200
          hover:bg-brand-50
          hover:text-brand-700
          sm:self-auto
        "
      >

        <Eye className="h-3 w-3" />
        Details

      </button>

    </div>

  );

}


/* ===============================================================
   RECOMMENDATION PREVIEW
=============================================================== */

function RecommendationPreview({
  recommendation,
  findings = [],
  sessions = [],
  onSelectSession,
}) {

  const title =
    recommendation?.title ||
    recommendation?.name ||
    'Security recommendation';


  const description =
    recommendation?.description ||
    recommendation?.detail ||
    'Apply the recommended security configuration to improve protection.';


  const action =
    recommendation?.action ||
    recommendation?.required_action ||
    recommendation?.remediation ||
    'Apply the relevant security policy.';


  const priority =
    recommendation?.priority ||
    recommendation?.severity ||
    recommendation?.level ||
    '';

  const priorityStyles = getSeverityStyles(priority);
  const affectedSessions = getAffectedSessions(recommendation, findings);


  return (

    <div className="
      group
      relative
      overflow-hidden
      rounded-xl
      border border-slate-200
      bg-white
      p-4
      transition-all
      hover:border-brand-200
      hover:shadow-sm
    ">

      {/* top accent line */}
      <div className="
        absolute inset-x-0 top-0 h-[3px]
        rounded-t-xl
        bg-gradient-to-r from-brand-400 to-brand-600
        opacity-0
        transition-opacity
        group-hover:opacity-100
      " />


      {/* priority badge */}
      {priority && (
        <span
          className={`
            mb-2.5
            inline-flex items-center
            rounded-full
            px-2 py-0.5
            text-[9px]
            font-bold
            uppercase
            tracking-wide
            ${priorityStyles.pill}
          `}
        >
          {priority}
        </span>
      )}


      <h3 className="
        text-sm
        font-semibold
        text-slate-800
        leading-snug
      ">
        {title}
      </h3>


      <p className="
        mt-1.5
        text-xs
        leading-5
        text-slate-500
        line-clamp-2
      ">
        {description}
      </p>

      {/* Target sessions pills */}
      {affectedSessions.length > 0 && (
        <div className="mt-2.5 flex flex-wrap items-center gap-1">
          <span className="text-[10px] font-semibold uppercase tracking-wider text-slate-400 mr-0.5">
            Sessions:
          </span>
          {affectedSessions.map((sId) => (
            <button
              key={sId}
              type="button"
              onClick={(e) => {
                e.stopPropagation();
                onSelectSession?.(sId);
              }}
              className="
                inline-flex items-center gap-1
                rounded
                border border-slate-200
                bg-slate-50
                px-1.5 py-0.5
                font-mono
                text-[10px]
                font-medium
                text-slate-600
                hover:border-brand-300 hover:bg-brand-50 hover:text-brand-700
                transition-colors
              "
              title={`View session ${sId}`}
            >
              <span className="h-1 w-1 rounded-full bg-amber-500" />
              {sId}
            </button>
          ))}
        </div>
      )}


      <div className="
        mt-3
        flex items-start
        gap-2
        rounded-lg
        bg-brand-50
        px-3 py-2.5
      ">

        <Sparkles className="
          mt-0.5
          h-3 w-3
          shrink-0
          text-brand-500
        " />

        <p className="
          text-xs
          leading-5
          text-brand-800
          font-medium
        ">
          {action}
        </p>

      </div>

    </div>

  );

}


/* ===============================================================
   FINDING DETAILS MODAL
=============================================================== */

function FindingDetailsModal({
  finding,
  onClose,
}) {

  const severity =
    finding?.severity ||
    finding?.level ||
    'INFO';


  const title =
    finding?.title ||
    finding?.name ||
    finding?.message ||
    'Security Finding';


  const description =
    finding?.description ||
    finding?.detail ||
    'No additional description is available.';


  const evidence =
    finding?.evidence ||
    finding?.details ||
    finding?.context ||
    'No additional evidence was provided.';


  const recommendation =
    finding?.recommendation ||
    finding?.remediation ||
    finding?.action ||
    'Review the affected configuration and apply the recommended security controls.';


  const severityStyle =
    getSeverityStyles(severity);


  return (

    <div
      className="
        fixed inset-0
        z-50
        flex items-end
        justify-center
        bg-slate-950/30
        p-4
        backdrop-blur-sm
        sm:items-center
      "
      onClick={onClose}
    >

      <div
        className="
          w-full
          max-w-2xl
          overflow-hidden
          rounded-2xl
          border border-slate-200
          bg-white
          shadow-2xl
        "
        onClick={(event) =>
          event.stopPropagation()
        }
      >


        {/* HEADER */}

        <div className="
          flex items-start
          justify-between
          gap-4
          border-b border-slate-100
          px-6 py-5
        ">

          <div className="
            flex items-start
            gap-3
          ">

            <div
              className={`
                flex h-10 w-10
                shrink-0
                items-center justify-center
                rounded-xl
                ${severityStyle.iconBg}
              `}
            >

              <FileWarning
                className={`
                  h-5 w-5
                  ${severityStyle.iconText}
                `}
              />

            </div>


            <div>

              <div className="
                flex items-center
                gap-2
              ">

                <span
                  className={`
                    rounded-md
                    border
                    px-2 py-1
                    text-[9px]
                    font-bold
                    uppercase
                    tracking-wide
                    ${severityStyle.badge}
                  `}
                >
                  {severity}
                </span>


                <span className="
                  text-[10px]
                  text-slate-400
                ">
                  Security Finding
                </span>

              </div>


              <h2 className="
                mt-2
                text-base
                font-semibold
                text-slate-900
              ">
                {title}
              </h2>

            </div>

          </div>


          <button
            type="button"
            onClick={onClose}
            className="
              flex h-8 w-8
              shrink-0
              items-center justify-center
              rounded-lg
              text-slate-400
              transition-colors
              hover:bg-slate-100
              hover:text-slate-700
            "
          >

            <X className="h-4 w-4" />

          </button>

        </div>


        {/* CONTENT */}

        <div className="
          max-h-[65vh]
          space-y-5
          overflow-y-auto
          px-6 py-5
        ">


          {/* DESCRIPTION */}

          <div>

            <p className="
              text-[10px]
              font-bold
              uppercase
              tracking-wide
              text-slate-400
            ">
              Description
            </p>


            <p className="
              mt-2
              text-sm
              leading-6
              text-slate-600
            ">
              {description}
            </p>

          </div>


          {/* EVIDENCE */}

          <div className="
            rounded-xl
            border border-slate-200
            bg-slate-50
            p-4
          ">

            <div className="
              flex items-center
              gap-2
            ">

              <Database className="
                h-4 w-4
                text-brand-600
              " />

              <p className="
                text-xs
                font-semibold
                text-slate-800
              ">
                Evidence & Context
              </p>

            </div>


            <pre className="
              mt-3
              whitespace-pre-wrap
              break-words
              text-xs
              leading-6
              text-slate-600
              font-sans
            ">
              {typeof evidence === 'string'
                ? evidence
                : JSON.stringify(
                    evidence,
                    null,
                    2
                  )}
            </pre>

          </div>


          {/* RECOMMENDED ACTION */}

          <div className="
            rounded-xl
            border border-brand-100
            bg-brand-50/50
            p-4
          ">

            <div className="
              flex items-center
              gap-2
            ">

              <Sparkles className="
                h-4 w-4
                text-brand-600
              " />

              <p className="
                text-[10px]
                font-bold
                uppercase
                tracking-wide
                text-brand-700
              ">
                Recommended Action
              </p>

            </div>


            <p className="
              mt-3
              text-sm
              font-medium
              leading-6
              text-slate-700
            ">
              {recommendation}
            </p>

          </div>

        </div>


        {/* FOOTER */}

        <div className="
          flex justify-end
          border-t border-slate-100
          px-6 py-4
        ">

          <button
            type="button"
            onClick={onClose}
            className="
              rounded-lg
              border border-slate-200
              bg-white
              px-4 py-2
              text-xs
              font-semibold
              text-slate-700
              transition-colors
              hover:bg-slate-50
            "
          >
            Close
          </button>

        </div>

      </div>

    </div>

  );

}


/* ===============================================================
   RISK STYLES
=============================================================== */

function getRiskStyles(level) {

  const normalized =
    String(level).toUpperCase();


  if (
    normalized.includes('CRITICAL')
  ) {

    return {

      iconBg: 'bg-rose-50',
      iconText: 'text-rose-600',

      badge:
        'border-rose-200 bg-rose-50 text-rose-700',

      scoreBorder: 'border-rose-500',
      scoreColor: '#f43f5e',

      heroGradient: {
        background:
          'linear-gradient(135deg, rgba(255,241,242,0.9) 0%, rgba(255,255,255,1) 60%)',
      },
      heroBorder: {
        borderColor: '#fecdd3',
      },

    };

  }


  if (
    normalized.includes('HIGH')
  ) {

    return {

      iconBg: 'bg-orange-50',
      iconText: 'text-orange-600',

      badge:
        'border-orange-200 bg-orange-50 text-orange-700',

      scoreBorder: 'border-orange-500',
      scoreColor: '#f97316',

      heroGradient: {
        background:
          'linear-gradient(135deg, rgba(255,247,237,0.9) 0%, rgba(255,255,255,1) 60%)',
      },
      heroBorder: {
        borderColor: '#fed7aa',
      },

    };

  }


  if (
    normalized.includes('MEDIUM')
  ) {

    return {

      iconBg: 'bg-amber-50',
      iconText: 'text-amber-600',

      badge:
        'border-amber-200 bg-amber-50 text-amber-700',

      scoreBorder: 'border-amber-500',
      scoreColor: '#f59e0b',

      heroGradient: {
        background:
          'linear-gradient(135deg, rgba(255,251,235,0.9) 0%, rgba(255,255,255,1) 60%)',
      },
      heroBorder: {
        borderColor: '#fde68a',
      },

    };

  }


  return {

    iconBg: 'bg-yellow-50',
    iconText: 'text-yellow-600',

    badge:
      'border-yellow-200 bg-yellow-50 text-yellow-700',

    scoreBorder: 'border-yellow-500',
    scoreColor: '#ca8a04',

          heroGradient: {
        background:
          'linear-gradient(135deg, rgba(254,252,232,0.9) 0%, rgba(255,255,255,1) 60%)',
      },
    heroBorder: {
      borderColor: '#fde047',
    },

  };

}


/* ===============================================================
   RISK TITLE
=============================================================== */

function getRiskTitle(level) {

  const normalized =
    String(level).toUpperCase();


  if (
    normalized.includes('CRITICAL')
  ) {

    return 'Critical security posture';

  }


  if (
    normalized.includes('HIGH')
  ) {

    return 'High-risk security posture';

  }


  if (
    normalized.includes('MEDIUM')
  ) {

    return 'Moderate security posture';

  }


  if (
    normalized.includes('LOW')
  ) {

    return 'Low-risk security posture';

  }


  return 'Security posture evaluated';

}


/* ===============================================================
   RISK SCORE RING
=============================================================== */

function RiskScoreRing({ score, riskStyles }) {

  const size = 72;
  const strokeWidth = 6;
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const clampedScore = Math.min(100, Math.max(0, score));
  const filled = (clampedScore / 100) * circumference;
  const gap = circumference - filled;

  return (

    <div className="relative flex items-center justify-center"
      style={{ width: size, height: size }}
    >

      <svg
        width={size}
        height={size}
        viewBox={`0 0 ${size} ${size}`}
        style={{ transform: 'rotate(-90deg)' }}
      >

        {/* Track */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke="#e2e8f0"
          strokeWidth={strokeWidth}
        />

        {/* Fill */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke={riskStyles.scoreColor}
          strokeWidth={strokeWidth}
          strokeLinecap="round"
          strokeDasharray={`${filled} ${gap}`}
        />

      </svg>


      <div className="
        absolute inset-0
        flex flex-col
        items-center
        justify-center
      ">

        <p className="
          text-lg
          font-bold
          leading-none
          text-slate-900
        ">
          {score}
        </p>

        <p className="
          mt-0.5
          text-[8px]
          font-bold
          uppercase
          tracking-wider
          text-slate-400
        ">
          /100
        </p>

      </div>

    </div>

  );

}


/* ===============================================================
   SEVERITY STYLES
=============================================================== */

function getSeverityStyles(severity) {

  const normalized =
    String(severity).toUpperCase();


  if (
    normalized.includes('CRITICAL')
  ) {

    return {
      iconBg: 'bg-rose-50',
      iconText: 'text-rose-600',
      badge: 'border-rose-200 bg-rose-50 text-rose-700',
      pill: 'bg-rose-100 text-rose-700',
      accentBar: 'bg-rose-400',
    };

  }


  if (
    normalized.includes('HIGH')
  ) {

    return {
      iconBg: 'bg-orange-50',
      iconText: 'text-orange-600',
      badge: 'border-orange-200 bg-orange-50 text-orange-700',
      pill: 'bg-orange-100 text-orange-700',
      accentBar: 'bg-orange-400',
    };

  }


  if (
    normalized.includes('MEDIUM')
  ) {

    return {
      iconBg: 'bg-amber-50',
      iconText: 'text-amber-600',
      badge: 'border-amber-200 bg-amber-50 text-amber-700',
      pill: 'bg-amber-100 text-amber-700',
      accentBar: 'bg-amber-400',
    };

  }


  if (normalized.includes('LOW')) {
    return {
      iconBg: 'bg-yellow-50',
      iconText: 'text-yellow-600',
      badge: 'border-yellow-200 bg-yellow-50 text-yellow-700',
      pill: 'bg-yellow-100 text-yellow-700',
      accentBar: 'bg-yellow-400',
    };
  }

  return {
    iconBg: 'bg-brand-50',
    iconText: 'text-brand-600',
    badge: 'border-brand-200 bg-brand-50 text-brand-700',
    pill: 'bg-brand-100 text-brand-700',
    accentBar: 'bg-brand-400',
  };

}