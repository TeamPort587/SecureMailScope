import React, { useState } from 'react';
import {
  FileArchive,
  Layers,
  ShieldAlert,
  Cpu,
  CheckCircle2,
  ArrowRight,
  Sparkles,
  Lock,
  Workflow,
  Radio,
  FileCode,
} from 'lucide-react';

const PIPELINE_STAGES = [
  {
    id: 1,
    title: 'PCAP Ingestion & Reassembly',
    short: 'Ingest & Reassemble',
    icon: FileArchive,
    badge: 'Raw Wire Capture',
    color: 'sky',
    summary:
      'Raw .pcap or .pcapng network capture files are ingested and indexed. Bidirectional TCP streams are reconstructed with sequence gap resolution.',
    details: [
      'Multi-format support for tcpdump, Wireshark, TShark, and Zeek captures',
      'Full TCP stream reconstruction across ephemeral ports and multi-session PCAPs',
      'Calculates stream duration, total packet count, byte volume, and client/server endpoints',
    ],
    technicalSpec: 'TCP Sequence Tracking · Zero-Copy Ingestion · Bidirectional Flow Engine',
  },
  {
    id: 2,
    title: 'Protocol & Handshake Dissection',
    short: 'Protocol Dissection',
    icon: Layers,
    badge: 'L7 Deep Inspection',
    color: 'brand',
    summary:
      'Parses Layer 7 email protocol commands and performs deep inspection of TLS handshakes, certificates, and negotiation flags.',
    details: [
      'Dissects SMTP (25, 465, 587), IMAP (143, 993), and POP3 (110, 995) conversations',
      'Inspects STARTTLS upgrades, TLS version (TLS 1.0 through 1.3), and cipher negotiation',
      'Extracts certificate validity, Subject Alternative Names, and Perfect Forward Secrecy (PFS)',
    ],
    technicalSpec: 'RFC 3207 (SMTP STARTTLS) · RFC 8314 (Mail TLS) · X.509 Certificate Chain',
  },
  {
    id: 3,
    title: 'Security & Compliance Engine',
    short: 'Security Heuristics',
    icon: ShieldAlert,
    badge: 'Deterministic Rules',
    color: 'amber',
    summary:
      'Evaluates every session against cryptographic standards, detecting plaintext authentication leaks, downgrade attacks, and weak ciphers.',
    details: [
      'Flags AUTH PLAIN and AUTH LOGIN transmitted over unencrypted connections',
      'Detects STARTTLS downgrade attempts and cleartext command injection attacks',
      'Verifies compliance with NIST SP 800-52r2 and BSI TR-03108 cryptographic guidelines',
    ],
    technicalSpec: 'Deterministic Compliance Matrix · Plaintext Credential Regex · CVE Heuristics',
  },
  {
    id: 4,
    title: 'AI Behavioral Anomaly Isolation',
    short: 'Anomaly Isolation',
    icon: Cpu,
    badge: 'Isolation Forest (if-v1)',
    color: 'indigo',
    summary:
      'Extracts a 30-dimensional feature vector per TCP stream and applies unsupervised machine learning to isolate behavioral and timing outliers.',
    details: [
      '30 features per session: byte entropy, timing intervals, command cadences, packet sizes',
      'Unsupervised Isolation Forest isolates anomalous traffic without requiring labeled training sets',
      'Computes decision scores with configurable contamination thresholds for outlier alerting',
    ],
    technicalSpec: 'Scikit-Learn Isolation Forest · 30-D Feature Vectorization · Outlier Ranking',
  },
  {
    id: 5,
    title: 'Actionable Remediation & Copilot',
    short: 'Remediation & Copilot',
    icon: Sparkles,
    badge: 'Automated Defense',
    color: 'emerald',
    summary:
      'Synthesizes findings into severity-ranked directives, generated Wireshark display filters, and AI Copilot forensic query assistance.',
    details: [
      'Exact configuration snippets for Postfix, Dovecot, Exim, and Sendmail mail transfer agents',
      'Wireshark display filters ready for one-click copy and deeper packet inspection',
      'AI Security Copilot providing interactive query assistance and threat triage',
    ],
    technicalSpec: 'RFC-Aligned Fix Directives · Wireshark Filter Generator · LLM Copilot Engine',
  },
];

export default function PipelineSection() {
  const [activeStageId, setActiveStageId] = useState(1);
  const activeStage = PIPELINE_STAGES.find((s) => s.id === activeStageId) || PIPELINE_STAGES[0];

  return (
    <section id="pipeline-section" className="py-12 sm:py-16 lg:py-20 border-t border-slate-200/80 dark:border-slate-800/80">
      <div className="mx-auto max-w-6xl px-4 sm:px-6 lg:px-8">
        
        {/* SECTION HEADER */}
        <div className="text-center max-w-3xl mx-auto">
          <div className="inline-flex items-center gap-2 rounded-full border border-brand-200 dark:border-brand-800/60 bg-brand-50/70 dark:bg-brand-950/50 px-3 py-1 text-xs font-semibold text-brand-600 dark:text-brand-400">
            <Workflow className="h-3.5 w-3.5" />
            <span>Inspection Architecture</span>
          </div>

          <h2 className="mt-3.5 text-2xl sm:text-3xl lg:text-4xl font-bold tracking-tight text-slate-900 dark:text-white">
            How SecureMailScope Inspects Traffic
          </h2>

          <p className="mt-2.5 text-sm sm:text-base text-slate-600 dark:text-slate-400">
            From raw packet captures to forensic findings — an automated, multi-layer analysis pipeline built for network and email security teams.
          </p>
        </div>

        {/* PIPELINE NAVIGATION BAR (PILL TABS) */}
        <div className="mt-10 sm:mt-12">
          {/* Horizontal Desktop Bar */}
          <div className="hidden md:grid md:grid-cols-5 gap-2 rounded-2xl border border-slate-200/80 dark:border-slate-800 bg-white/80 dark:bg-slate-900/80 p-1.5 shadow-sm backdrop-blur-md">
            {PIPELINE_STAGES.map((stage) => {
              const Icon = stage.icon;
              const isActive = stage.id === activeStageId;

              return (
                <button
                  key={stage.id}
                  type="button"
                  onClick={() => setActiveStageId(stage.id)}
                  className={`group relative flex items-center gap-2.5 rounded-xl px-3 py-3 text-left transition-all duration-200 cursor-pointer ${
                    isActive
                      ? 'bg-brand-500/10 dark:bg-brand-500/15 border border-brand-300 dark:border-brand-600/50 text-brand-700 dark:text-brand-300 shadow-xs'
                      : 'hover:bg-slate-100/70 dark:hover:bg-slate-800/60 border border-transparent text-slate-600 dark:text-slate-400'
                  }`}
                >
                  <div
                    className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-lg font-mono text-xs font-bold transition-colors ${
                      isActive
                        ? 'bg-brand-600 dark:bg-brand-500 text-white shadow-xs'
                        : 'bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-400 group-hover:bg-slate-200 dark:group-hover:bg-slate-700'
                    }`}
                  >
                    0{stage.id}
                  </div>

                  <div className="min-w-0 flex-1">
                    <p className={`truncate text-xs font-bold ${isActive ? 'text-brand-700 dark:text-brand-300' : 'text-slate-700 dark:text-slate-200'}`}>
                      {stage.short}
                    </p>
                    <p className="truncate text-[10px] text-slate-400 dark:text-slate-500">
                      {stage.badge}
                    </p>
                  </div>
                </button>
              );
            })}
          </div>

          {/* Mobile Scrollable Horizontal Bar */}
          <div className="flex md:hidden gap-2 overflow-x-auto pb-2 scrollbar-none">
            {PIPELINE_STAGES.map((stage) => {
              const isActive = stage.id === activeStageId;
              return (
                <button
                  key={stage.id}
                  type="button"
                  onClick={() => setActiveStageId(stage.id)}
                  className={`shrink-0 flex items-center gap-2 rounded-xl px-3.5 py-2.5 text-xs font-semibold border transition ${
                    isActive
                      ? 'border-brand-500 bg-brand-50 dark:bg-brand-950/60 text-brand-600 dark:text-brand-300'
                      : 'border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 text-slate-600 dark:text-slate-400'
                  }`}
                >
                  <span className="font-mono text-[11px] font-bold">0{stage.id}</span>
                  <span>{stage.short}</span>
                </button>
              );
            })}
          </div>
        </div>

        {/* ACTIVE STAGE SHOWCASE CARD */}
        <div className="mt-4 rounded-2xl border border-slate-200/90 dark:border-slate-800 bg-white dark:bg-slate-900 shadow-md overflow-hidden transition-all duration-300">
          <div className="grid grid-cols-1 lg:grid-cols-12 divide-y lg:divide-y-0 lg:divide-x divide-slate-100 dark:divide-slate-800">
            
            {/* LEFT / MAIN COLUMN: Details & Capabilities */}
            <div className="p-6 sm:p-8 lg:col-span-7">
              <div className="flex items-center gap-3">
                <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-brand-500/10 border border-brand-500/20 text-brand-600 dark:text-brand-400 shadow-sm">
                  {React.createElement(activeStage.icon, { className: 'h-5 w-5' })}
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs font-bold text-brand-600 dark:text-brand-400">
                      STAGE 0{activeStage.id}
                    </span>
                    <span className="text-slate-300 dark:text-slate-700">·</span>
                    <span className="inline-flex items-center rounded-full bg-slate-100 dark:bg-slate-800 px-2 py-0.5 font-mono text-[10px] font-medium text-slate-600 dark:text-slate-400">
                      {activeStage.badge}
                    </span>
                  </div>
                  <h3 className="text-lg sm:text-xl font-bold text-slate-900 dark:text-white tracking-tight">
                    {activeStage.title}
                  </h3>
                </div>
              </div>

              <p className="mt-4 text-sm text-slate-600 dark:text-slate-300 leading-relaxed">
                {activeStage.summary}
              </p>

              <div className="mt-6 space-y-3">
                <p className="text-[11px] font-bold uppercase tracking-wider text-slate-400 dark:text-slate-500">
                  Key Inspection Capabilities
                </p>
                {activeStage.details.map((detail, idx) => (
                  <div key={idx} className="flex items-start gap-2.5">
                    <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-500 mt-0.5" />
                    <span className="text-xs text-slate-700 dark:text-slate-300 leading-relaxed font-normal">
                      {detail}
                    </span>
                  </div>
                ))}
              </div>

              <div className="mt-8 flex items-center justify-between border-t border-slate-100 dark:border-slate-800 pt-4">
                <span className="text-xs text-slate-500 dark:text-slate-400">
                  Step {activeStage.id} of {PIPELINE_STAGES.length}
                </span>

                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    disabled={activeStageId <= 1}
                    onClick={() => setActiveStageId((prev) => Math.max(1, prev - 1))}
                    className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 px-3 py-1.5 text-xs font-semibold text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer transition"
                  >
                    Previous
                  </button>

                  <button
                    type="button"
                    disabled={activeStageId >= PIPELINE_STAGES.length}
                    onClick={() => setActiveStageId((prev) => Math.min(PIPELINE_STAGES.length, prev + 1))}
                    className="inline-flex items-center gap-1.5 rounded-lg bg-brand-600 dark:bg-brand-500 px-3 py-1.5 text-xs font-semibold text-white hover:bg-brand-700 dark:hover:bg-brand-400 disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer transition shadow-xs"
                  >
                    <span>Next</span>
                    <ArrowRight className="h-3 w-3" />
                  </button>
                </div>
              </div>
            </div>

            {/* RIGHT COLUMN: Technical Spec & Data Flow Box */}
            <div className="p-6 sm:p-8 lg:col-span-5 bg-slate-50/70 dark:bg-slate-850/50 flex flex-col justify-between">
              <div>
                <div className="flex items-center gap-2 text-xs font-semibold text-slate-700 dark:text-slate-300">
                  <FileCode className="h-4 w-4 text-brand-600 dark:text-brand-400" />
                  <span>Standards & Protocol Telemetry</span>
                </div>

                <div className="mt-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-4 font-mono text-xs">
                  <p className="text-[10px] text-slate-400 dark:text-slate-500 uppercase font-sans font-bold">
                    Engine Pipeline Specification
                  </p>
                  <p className="mt-1 text-slate-800 dark:text-slate-200 font-semibold leading-relaxed">
                    {activeStage.technicalSpec}
                  </p>
                </div>

                <div className="mt-4 space-y-2.5">
                  <div className="rounded-xl border border-slate-200/80 dark:border-slate-800/80 bg-white/80 dark:bg-slate-900/80 p-3">
                    <p className="text-[10px] uppercase font-bold text-slate-400 dark:text-slate-500">
                      Pipeline Input
                    </p>
                    <p className="mt-0.5 text-xs text-slate-700 dark:text-slate-300">
                      {activeStage.id === 1 && 'Binary .pcap / .pcapng network stream packets'}
                      {activeStage.id === 2 && 'Reconstructed bidirectional TCP byte streams'}
                      {activeStage.id === 3 && 'L7 protocol commands, TLS parameters & certificates'}
                      {activeStage.id === 4 && 'Normalized 30-feature vector matrix per session'}
                      {activeStage.id === 5 && 'Aggregated security findings, anomaly scores & PCAP'}
                    </p>
                  </div>

                  <div className="rounded-xl border border-slate-200/80 dark:border-slate-800/80 bg-white/80 dark:bg-slate-900/80 p-3">
                    <p className="text-[10px] uppercase font-bold text-slate-400 dark:text-slate-500">
                      Pipeline Output
                    </p>
                    <p className="mt-0.5 text-xs text-slate-700 dark:text-slate-300">
                      {activeStage.id === 1 && 'Ordered TCP streams indexed by stream ID & endpoints'}
                      {activeStage.id === 2 && 'Extracted SMTP/IMAP/POP3 state and TLS negotiation'}
                      {activeStage.id === 3 && 'Categorized findings (CRITICAL, HIGH, MEDIUM, LOW, INFO)'}
                      {activeStage.id === 4 && 'Decision score, anomaly classification, outlier ranking'}
                      {activeStage.id === 5 && 'Executive dashboard, fix snippets & Wireshark filters'}
                    </p>
                  </div>
                </div>
              </div>

              <div className="mt-6 flex items-center gap-2 text-[11px] text-slate-500 dark:text-slate-400">
                <Radio className="h-3.5 w-3.5 text-emerald-500 animate-pulse" />
                <span>Deterministic protocol verification active</span>
              </div>
            </div>

          </div>
        </div>

      </div>
    </section>
  );
}
