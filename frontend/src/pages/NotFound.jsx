import React from 'react';
import { Link } from 'react-router-dom';
import { ShieldAlert, ArrowLeft } from 'lucide-react';

export default function NotFound() {
  return (
    <div className="max-w-md mx-auto px-4 py-24 text-center space-y-4">
      <div className="w-16 h-16 rounded-2xl bg-slate-900 border border-slate-800 flex items-center justify-center text-amber-400 mx-auto">
        <ShieldAlert className="w-8 h-8" />
      </div>
      <h1 className="text-2xl font-bold text-white">404 — Page Not Found</h1>
      <p className="text-xs text-slate-400 leading-relaxed">
        The requested security route does not exist. Return to the dashboard to launch a new email capture analysis.
      </p>
      <Link
        to="/"
        className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-brand-600 hover:bg-brand-500 text-white text-xs font-semibold shadow-lg shadow-brand-500/20 transition-all"
      >
        <ArrowLeft className="w-4 h-4" />
        <span>Return to Dashboard</span>
      </Link>
    </div>
  );
}
