import React, { useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import { useAnalysis } from '../hooks/useAnalysis';
import RiskSummary from '../components/RiskSummary';
import SessionTable from '../components/SessionTable';
import FindingsList from '../components/FindingsList';
import Recommendations from '../components/Recommendations';
import LoadingState from '../components/LoadingState';
import ErrorState from '../components/ErrorState';
import { ArrowLeft, Download, RefreshCw } from 'lucide-react';

export default function Analysis() {
  const { id } = useParams();
  const { analysis, loading, error, fetchAnalysis, exportJson } = useAnalysis(id);

  useEffect(() => {
    if (id) {
      fetchAnalysis(id);
    }
  }, [id, fetchAnalysis]);

  if (loading) {
    return (
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-16">
        <LoadingState
          message="Retrieving Analysis from Node.js Gateway..."
          subtext={`Fetching record ID: ${id}`}
        />
      </div>
    );
  }

  if (error || !analysis) {
    return (
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-16 space-y-4">
        <Link
          to="/"
          className="inline-flex items-center gap-1.5 text-xs text-brand-400 hover:underline"
        >
          <ArrowLeft className="w-3.5 h-3.5" />
          <span>Back to Dashboard</span>
        </Link>
        <ErrorState
          title="Analysis Record Unavailable"
          message={error || 'Could not find or retrieve analysis data for this capture ID.'}
          onRetry={() => fetchAnalysis(id)}
        />
      </div>
    );
  }

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8 animate-in fade-in duration-300">
      {/* Top Breadcrumb & Action Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-4 rounded-xl bg-slate-900/60 border border-slate-800">
        <div className="space-y-1">
          <Link
            to="/"
            className="inline-flex items-center gap-1.5 text-xs text-brand-400 hover:text-brand-300 font-medium"
          >
            <ArrowLeft className="w-3.5 h-3.5" />
            <span>Back to Dashboard</span>
          </Link>
          <h2 className="text-lg font-bold text-white font-mono flex items-center gap-2">
            <span>{analysis.filename}</span>
            <span className="text-xs text-slate-400 font-normal">({analysis.analysis_id})</span>
          </h2>
        </div>

        <div className="flex items-center gap-2 self-end sm:self-auto">
          <button
            onClick={() => fetchAnalysis(id)}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors"
            title="Reload from Node.js Gateway"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            <span>Refresh</span>
          </button>
          <button
            onClick={() => exportJson(analysis.analysis_id)}
            className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-brand-600 hover:bg-brand-500 text-white shadow-md shadow-brand-500/20 transition-colors"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export Report JSON</span>
          </button>
        </div>
      </div>

      {/* Risk Summary */}
      <RiskSummary
        risk={analysis.risk}
        summary={analysis.summary}
        sessions={analysis.sessions}
        filename={analysis.filename}
        uploadedAt={analysis.uploaded_at}
      />

      {/* Sessions Table */}
      <SessionTable
        sessions={analysis.sessions}
        findings={analysis.findings}
      />

      {/* Findings */}
      <FindingsList findings={analysis.findings} />

      {/* Recommendations */}
      <Recommendations recommendations={analysis.recommendations} />
    </div>
  );
}
