import React, { useState } from 'react';
import UploadForm from '../components/UploadForm';
import UploadProgress from '../components/UploadProgress';
import RiskSummary from '../components/RiskSummary';
import SessionTable from '../components/SessionTable';
import FindingsList from '../components/FindingsList';
import Recommendations from '../components/Recommendations';
import ErrorState from '../components/ErrorState';
import { Download, RefreshCw, Layers, Bug, Lightbulb, Sparkles } from 'lucide-react';
import { DEMO_PRESETS } from '../mock/demoCaptures';

export default function Dashboard({ analysisHook }) {
  const { analysis, uploading, error, uploadPcap, exportJson, loadPreset, setError } = analysisHook;
  const [activeTab, setActiveTab] = useState('all'); // 'all' | 'sessions' | 'findings' | 'recommendations'

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
      {/* Hero / Upload Section */}
      <div className="rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/50 p-6 sm:p-8 backdrop-blur-sm relative overflow-hidden shadow-sm">
        <div className="max-w-3xl space-y-2 mb-6">
          <div className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-brand-50 dark:bg-brand-500/10 text-brand-700 dark:text-brand-400 text-xs font-mono border border-brand-200 dark:border-brand-500/20 font-semibold">
            <span className="w-1.5 h-1.5 rounded-full bg-brand-500 dark:bg-brand-400 animate-pulse" />
            <span>Autonomous PCAP Dissection Engine</span>
          </div>
          <h1 className="text-2xl sm:text-4xl font-extrabold tracking-tight text-slate-900 dark:text-white">
            Email Protocol Security Inspector
          </h1>
          <p className="text-sm sm:text-base text-slate-600 dark:text-slate-400 leading-relaxed">
            Upload raw <span className="font-mono text-slate-800 dark:text-slate-300">.pcap</span> or <span className="font-mono text-slate-800 dark:text-slate-300">.pcapng</span> network captures to reconstruct SMTP, IMAP, and POP3 streams, detect STARTTLS stripping, pinpoint unencrypted credentials, and calculate machine learning risk scores.
          </p>
        </div>

        {uploading ? (
          <UploadProgress />
        ) : (
          <UploadForm onUpload={uploadPcap} uploading={uploading} />
        )}

        {/* Quick Demo Previews */}
        {!analysis && !uploading && (
          <div className="mt-8 pt-6 border-t border-slate-200 dark:border-slate-800/80">
            <div className="flex items-center gap-2 text-xs font-semibold text-slate-700 dark:text-slate-300 mb-3">
              <Sparkles className="w-4 h-4 text-brand-600 dark:text-brand-400" />
              <span>Or explore sample captures without uploading:</span>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              {DEMO_PRESETS.map((demo) => (
                <button
                  key={demo.id}
                  onClick={() => loadPreset(demo.data)}
                  className="p-3 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/80 hover:bg-slate-50 dark:hover:bg-slate-800/80 hover:border-slate-300 dark:hover:border-slate-700 text-left transition-all group flex flex-col justify-between shadow-xs"
                >
                  <div className="space-y-1">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-bold text-slate-800 dark:text-slate-200 group-hover:text-brand-600 dark:group-hover:text-brand-300 transition-colors">
                        {demo.name.split(':')[1] || demo.name}
                      </span>
                    </div>
                    <p className="text-[11px] text-slate-500 dark:text-slate-400 line-clamp-2">{demo.description}</p>
                  </div>
                  <div className="mt-2.5 pt-2 border-t border-slate-100 dark:border-slate-800/60 flex items-center justify-between">
                    <span className={`text-[10px] px-2 py-0.5 rounded border font-mono ${demo.badgeClass}`}>
                      {demo.badge}
                    </span>
                    <span className="text-[10px] text-brand-600 dark:text-brand-400 font-semibold">Load capture →</span>
                  </div>
                </button>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Global Error Banner */}
      {error && (
        <ErrorState
          title="Analysis Request Failed"
          message={error}
          onRetry={() => setError(null)}
        />
      )}

      {/* Active Analysis Dashboard */}
      {analysis && (
        <div className="space-y-8 animate-in fade-in duration-300">
          {/* Top Actions: Export JSON, Reload */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-4 rounded-xl bg-white dark:bg-slate-900/40 border border-slate-200 dark:border-slate-800 shadow-sm">
            <div>
              <span className="text-[11px] uppercase tracking-wider text-slate-500 font-mono block">Active Inspection</span>
              <h3 className="text-sm font-bold text-slate-900 dark:text-white font-mono flex items-center gap-2">
                <span>{analysis.filename || 'packet_capture.pcap'}</span>
                <span className="text-xs text-slate-500">({analysis.analysis_id})</span>
              </h3>
            </div>

            <div className="flex items-center gap-2 self-end sm:self-auto">
              <button
                onClick={() => exportJson(analysis.analysis_id)}
                className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-brand-600 hover:bg-brand-500 text-white shadow-md shadow-brand-500/20 transition-colors"
                title="Download authoritative analysis report JSON"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Export Report JSON</span>
              </button>
            </div>
          </div>

          {/* Risk Overview */}
          <RiskSummary
            risk={analysis.risk}
            summary={analysis.summary}
            filename={analysis.filename}
            uploadedAt={analysis.uploaded_at}
          />

          {/* Section Navigation Tabs */}
          <div className="flex items-center gap-2 border-b border-slate-200 dark:border-slate-800 pb-3">
            <button
              onClick={() => setActiveTab('all')}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors ${
                activeTab === 'all'
                  ? 'bg-brand-50 dark:bg-slate-800 text-brand-700 dark:text-white border border-brand-200/80 dark:border-transparent shadow-xs'
                  : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-900'
              }`}
            >
              Unified Overview
            </button>
            <button
              onClick={() => setActiveTab('sessions')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors ${
                activeTab === 'sessions'
                  ? 'bg-brand-50 dark:bg-slate-800 text-brand-700 dark:text-white border border-brand-200/80 dark:border-transparent shadow-xs'
                  : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-900'
              }`}
            >
              <Layers className="w-3.5 h-3.5 text-brand-600 dark:text-brand-400" />
              <span>Sessions ({analysis.sessions?.length || 0})</span>
            </button>
            <button
              onClick={() => setActiveTab('findings')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors ${
                activeTab === 'findings'
                  ? 'bg-brand-50 dark:bg-slate-800 text-brand-700 dark:text-white border border-brand-200/80 dark:border-transparent shadow-xs'
                  : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-900'
              }`}
            >
              <Bug className="w-3.5 h-3.5 text-amber-500 dark:text-amber-400" />
              <span>Findings ({analysis.findings?.length || 0})</span>
            </button>
            <button
              onClick={() => setActiveTab('recommendations')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors ${
                activeTab === 'recommendations'
                  ? 'bg-brand-50 dark:bg-slate-800 text-brand-700 dark:text-white border border-brand-200/80 dark:border-transparent shadow-xs'
                  : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-900'
              }`}
            >
              <Lightbulb className="w-3.5 h-3.5 text-emerald-500 dark:text-emerald-400" />
              <span>Recommendations ({analysis.recommendations?.length || 0})</span>
            </button>
          </div>

          {/* Conditional Tab Rendering */}
          {(activeTab === 'all' || activeTab === 'sessions') && (
            <section aria-labelledby="sessions-heading">
              <SessionTable
                sessions={analysis.sessions}
                findings={analysis.findings}
              />
            </section>
          )}

          {(activeTab === 'all' || activeTab === 'findings') && (
            <section aria-labelledby="findings-heading">
              <FindingsList findings={analysis.findings} />
            </section>
          )}

          {(activeTab === 'all' || activeTab === 'recommendations') && (
            <section aria-labelledby="recommendations-heading">
              <Recommendations recommendations={analysis.recommendations} />
            </section>
          )}
        </div>
      )}
    </div>
  );
}
