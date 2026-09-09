import React from 'react';

export default function Footer() {
  return (
    <footer className="border-t border-slate-100 bg-white">
      <div className="mx-auto flex min-h-[44px] w-full max-w-7xl items-center justify-between px-4 sm:px-6 lg:px-8">
        <p className="text-[10px] text-slate-400">
          SecureMailScope
          <span className="mx-1.5 text-slate-300">·</span>
          Email Security Analysis
        </p>

        <div className="flex items-center gap-3">
          <span className="hidden text-[10px] text-slate-400 sm:inline">
            SMTP · IMAP · POP3
          </span>

          <span className="h-1 w-1 rounded-full bg-slate-300" />

          <span className="text-[10px] font-medium text-slate-400">
            SIH 2026
          </span>
        </div>
      </div>
    </footer>
  );
}