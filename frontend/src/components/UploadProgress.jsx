import React, { useState, useEffect } from 'react';
import { Loader2, ShieldAlert, Cpu, Activity, Database } from 'lucide-react';

const STAGES = [
  { label: 'Ingesting PCAP into Gateway...', icon: Database },
  { label: 'Reconstructing TCP streams & email sessions...', icon: Activity },
  { label: 'Evaluating protocol security rules & TLS handshakes...', icon: Cpu },
  { label: 'Running ML risk classification & heuristic scoring...', icon: ShieldAlert },
];

export default function UploadProgress() {
  const [currentStage, setCurrentStage] = useState(0);

  useEffect(() => {
    const timer = setInterval(() => {
      setCurrentStage((prev) => (prev < STAGES.length - 1 ? prev + 1 : prev));
    }, 1200);
    return () => clearInterval(timer);
  }, []);

  const ActiveIcon = STAGES[currentStage].icon;

  return (
    <div className="w-full p-8 rounded-2xl bg-slate-900/90 border border-brand-500/30 shadow-2xl backdrop-blur-md text-center">
      <div className="relative flex items-center justify-center mb-5">
        <div className="w-14 h-14 rounded-2xl bg-brand-500/10 border border-brand-500/30 flex items-center justify-center text-brand-400 animate-pulse">
          <ActiveIcon className="w-7 h-7" />
        </div>
      </div>

      <h3 className="text-base font-semibold text-slate-100">Analysis In Progress</h3>
      <p className="text-xs text-brand-400 font-mono mt-1 transition-all duration-300">
        {STAGES[currentStage].label}
      </p>

      {/* Progress Bar */}
      <div className="w-full bg-slate-800 h-2 rounded-full mt-5 overflow-hidden">
        <div
          className="bg-gradient-to-r from-brand-500 to-sky-400 h-full rounded-full transition-all duration-500 ease-out animate-pulse"
          style={{ width: `${((currentStage + 1) / STAGES.length) * 100}%` }}
        />
      </div>

      <p className="text-[11px] text-slate-500 mt-3">
        Extracting TLS parameters, certificate validation chain, and protocol compliance
      </p>
    </div>
  );
}
