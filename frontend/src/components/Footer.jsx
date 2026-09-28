import React from 'react';
import { Link } from 'react-router-dom';
import { Shield } from 'lucide-react';

const LINKS = [
  { label: 'Dashboard', to: '/' },
  { label: 'Analysis', to: '/analysis' },
  { label: 'History', to: '/history' },
];

export default function Footer() {

  return (

    <footer className="
      border-t border-slate-100 dark:border-slate-800
      bg-white dark:bg-slate-900 px-5 py-4 sm:px-7
    ">

      <div className="
        flex flex-col gap-3
        sm:flex-row sm:items-center sm:justify-between
      ">

        {/* Brand */}
        <div className="flex items-center gap-2">

          <img
            src="/SMS.png"
            alt="SecureMailScope"
            className="h-11 w-11 shrink-0 object-contain"
          />

          <div className="flex flex-col justify-center leading-none translate-y-1">
            <p className="text-[13px] font-bold tracking-tight leading-tight">
              <span className="text-slate-700 dark:text-slate-200">Secure</span>
              <span className="text-brand-600 dark:text-brand-400">Mail</span>
              <span className="text-slate-700 dark:text-slate-200">Scope</span>
            </p>
            <p className="text-[9px] text-slate-400 dark:text-slate-500 mt-[3px]">
              Email traffic security analysis
            </p>
          </div>

        </div>


        {/* Right */}
        <p className="text-[10px] text-slate-400">
          © 2026 Team PORT587 · PS ID 26159
        </p>

      </div>

    </footer>

  );

}