import React from 'react';
import { Terminal, Check, Copy } from 'lucide-react';

export default function EvidencePanel({ evidence }) {
  const [copied, setCopied] = React.useState(false);

  if (!evidence || Object.keys(evidence).length === 0) {
    return (
      <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800 text-slate-500 text-xs italic">
        No additional packet evidence attributes attached to this finding.
      </div>
    );
  }

  const jsonString = JSON.stringify(evidence, null, 2);

  const handleCopy = () => {
    navigator.clipboard.writeText(jsonString);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="rounded-xl bg-slate-950/80 border border-slate-800/80 overflow-hidden font-mono text-xs">
      <div className="px-3.5 py-2 bg-slate-900/80 border-b border-slate-800 flex items-center justify-between text-[11px] text-slate-400">
        <div className="flex items-center gap-1.5 text-brand-400">
          <Terminal className="w-3.5 h-3.5" />
          <span className="font-semibold text-slate-300">Packet Dissector Evidence</span>
        </div>
        <button
          onClick={handleCopy}
          className="inline-flex items-center gap-1 px-2 py-0.5 rounded hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition-colors"
          title="Copy raw evidence JSON"
        >
          {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
          <span>{copied ? 'Copied' : 'Copy'}</span>
        </button>
      </div>

      {/* Formatted Key-Value Grid */}
      <div className="p-3.5 space-y-1.5 divide-y divide-slate-800/40">
        {Object.entries(evidence).map(([key, val]) => (
          <div key={key} className="pt-1.5 first:pt-0 flex flex-col sm:flex-row sm:items-baseline justify-between gap-1">
            <span className="text-slate-400 text-[11px] font-sans">{key.replace(/_/g, ' ')}:</span>
            <span className="text-slate-200 text-xs font-mono font-medium break-all">
              {typeof val === 'boolean' ? (
                <span className={val ? 'text-amber-400' : 'text-slate-400'}>
                  {val ? 'TRUE' : 'FALSE'}
                </span>
              ) : typeof val === 'object' && val !== null ? (
                JSON.stringify(val)
              ) : (
                String(val)
              )}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
