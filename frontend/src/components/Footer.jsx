import React from 'react';
import { Shield, Layers, ArrowRight } from 'lucide-react';

export default function Footer() {
  return (
    <footer className="w-full border-t border-slate-800/80 bg-slate-950/60 py-6 mt-16 text-xs text-slate-500">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col md:flex-row items-center justify-between gap-4">
        <div className="flex items-center gap-2">
          <Shield className="w-4 h-4 text-brand-400" />
          <span className="text-slate-400 font-medium">SecureMailScope</span>
          <span>&copy; {new Date().getFullYear()} — Production-Ready MVP</span>
        </div>

        {/* System Architecture Boundary Notice */}
        <div className="flex items-center gap-2 font-mono text-[11px] bg-slate-900/80 px-3 py-1.5 rounded-lg border border-slate-800">
          <Layers className="w-3.5 h-3.5 text-brand-400" />
          <span className="text-brand-300">React Frontend</span>
          <ArrowRight className="w-3 h-3 text-slate-600" />
          <span className="text-sky-300">Node.js Gateway</span>
          <ArrowRight className="w-3 h-3 text-slate-600" />
          <span className="text-purple-300">Django Engine</span>
        </div>

        <div className="flex items-center gap-4 text-[11px] text-slate-500">
          <span>Contract: node-react-analysis-response.json</span>
          <span>•</span>
          <span>RF-ML + Rule Engine</span>
        </div>
      </div>
    </footer>
  );
}
