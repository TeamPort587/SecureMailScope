import React, { useEffect, useRef, useState } from 'react';
import { NavLink, Link } from 'react-router-dom';
import {
  FileSearch,
  FileUp,
  FlaskConical,
  User,
  LogOut,
  Database,
  ArrowRight,
  History,
  ShieldCheck,
} from 'lucide-react';

import { DEMO_PRESETS } from '../mock/demoCaptures';

export default function Navbar({ onLoadPreset, onResetAnalysis, onLogout, user }) {
  const [demoOpen, setDemoOpen] = useState(false);
  const [profileOpen, setProfileOpen] = useState(false);

  const demoRef = useRef(null);
  const profileRef = useRef(null);

  useEffect(() => {
    const handleOutsideClick = (event) => {
      if (demoRef.current && !demoRef.current.contains(event.target)) {
        setDemoOpen(false);
      }
      if (profileRef.current && !profileRef.current.contains(event.target)) {
        setProfileOpen(false);
      }
    };
    document.addEventListener('mousedown', handleOutsideClick);
    return () => document.removeEventListener('mousedown', handleOutsideClick);
  }, []);

  const handlePreset = (preset) => {
    if (onLoadPreset) onLoadPreset(preset.data);
    setDemoOpen(false);
  };

  const rawUsername = user?.email?.split('@')[0] || 'User';
  const displayName = rawUsername.charAt(0).toUpperCase() + rawUsername.slice(1);

  return (
    <header className="sticky top-0 z-50 w-full border-b border-slate-200/80 bg-white/90 backdrop-blur-md">
      <div className="mx-auto flex h-16 max-w-7xl items-center justify-between px-4 sm:px-6 lg:px-8">
        
        {/* LEFT: BRAND LOGO */}
        <Link
          to="/"
          onClick={onResetAnalysis}
          className="group flex items-center gap-3 transition-opacity hover:opacity-95"
        >
          <img
            src="/SMS.png"
            alt="SecureMailScope"
            className="h-11 w-11 shrink-0 object-contain drop-shadow-sm transition-transform group-hover:scale-105"
          />
          <div className="flex flex-col justify-center">
            <span className="text-lg sm:text-xl font-extrabold tracking-tight leading-tight text-slate-900">
              Secure<span className="text-brand-600">Mail</span>Scope
            </span>
            <span className="mt-0.5 text-xs font-medium text-slate-500 tracking-tight leading-none">
              Email Security Analysis
            </span>
          </div>
        </Link>

        {/* RIGHT: ICON BUTTON GROUP WITH HOVER TOOLTIPS */}
        <nav className="flex items-center gap-2.5">
          
          {/* 1. UPLOAD PCAP / DASHBOARD */}
          <div className="relative group">
            <NavLink
              to="/"
              end
              onClick={onResetAnalysis}
              className={({ isActive }) =>
                `relative flex h-10 w-10 items-center justify-center rounded-xl border transition-all duration-150 hover:-translate-y-0.5 active:translate-y-0 ${
                  isActive
                    ? 'border-brand-400 bg-brand-50 text-brand-600 shadow-[0_2px_0_0_#38bdf8]'
                    : 'border-slate-200/90 bg-white/90 text-slate-600 hover:border-slate-300 hover:bg-slate-50 hover:text-slate-900 hover:shadow-[0_2px_0_0_#cbd5e1]'
                }`
              }
            >
              <FileUp className="h-4.5 w-4.5" />
            </NavLink>
            <NavTooltip label="UPLOAD" />
          </div>

          {/* 2. ANALYSIS CENTER */}
          <div className="relative group">
            <NavLink
              to="/analysis"
              className={({ isActive }) =>
                `relative flex h-10 w-10 items-center justify-center rounded-xl border transition-all duration-150 hover:-translate-y-0.5 active:translate-y-0 ${
                  isActive
                    ? 'border-brand-400 bg-brand-50 text-brand-600 shadow-[0_2px_0_0_#38bdf8]'
                    : 'border-slate-200/90 bg-white/90 text-slate-600 hover:border-slate-300 hover:bg-slate-50 hover:text-slate-900 hover:shadow-[0_2px_0_0_#cbd5e1]'
                }`
              }
            >
              <FileSearch className="h-4.5 w-4.5" />
            </NavLink>
            <NavTooltip label="ANALYSIS" />
          </div>

          {/* 3. DEMO CAPTURES */}
          <div className="relative group" ref={demoRef}>
            <button
              type="button"
              onClick={() => {
                setDemoOpen(!demoOpen);
                setProfileOpen(false);
              }}
              className={`relative flex h-10 w-10 items-center justify-center rounded-xl border transition-all duration-150 hover:-translate-y-0.5 active:translate-y-0 ${
                demoOpen
                  ? 'border-brand-400 bg-brand-50 text-brand-600 shadow-[0_2px_0_0_#38bdf8]'
                  : 'border-slate-200/90 bg-white/90 text-slate-600 hover:border-slate-300 hover:bg-slate-50 hover:text-slate-900 hover:shadow-[0_2px_0_0_#cbd5e1]'
              }`}
            >
              <FlaskConical className="h-4.5 w-4.5" />
            </button>
            <NavTooltip label="DEMO" hidden={demoOpen} />

            {/* DEMO POPOVER */}
            {demoOpen && (
              <div className="absolute right-0 top-12 z-50 w-80 overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-xl animate-in fade-in zoom-in-95 duration-150">
                <div className="border-b border-slate-100 bg-slate-50/70 px-4 py-3">
                  <div className="flex items-center gap-2">
                    <FlaskConical className="h-4 w-4 text-brand-600" />
                    <p className="text-xs font-semibold text-slate-900">Demo PCAP Captures</p>
                  </div>
                  <p className="text-[10px] text-slate-500 mt-0.5">
                    Inspect realistic email security traffic captures
                  </p>
                </div>

                <div className="max-h-[320px] overflow-y-auto p-2 space-y-1">
                  {DEMO_PRESETS.map((preset) => (
                    <button
                      key={preset.id}
                      type="button"
                      onClick={() => handlePreset(preset)}
                      className="group/item flex w-full items-start gap-2.5 rounded-xl p-2.5 text-left transition-colors hover:bg-brand-50/60"
                    >
                      <div className="mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-lg border border-brand-100 bg-brand-50 text-brand-600 transition-colors group-hover/item:bg-brand-100">
                        <Database className="h-3.5 w-3.5" />
                      </div>
                      <div className="min-w-0 flex-1">
                        <p className="truncate text-xs font-semibold text-slate-800 group-hover/item:text-brand-700">
                          {preset.name.split(':')[1]?.trim() || preset.name}
                        </p>
                        <p className="mt-0.5 line-clamp-2 text-[10px] leading-4 text-slate-500">
                          {preset.description}
                        </p>
                      </div>
                      <ArrowRight className="mt-1 h-3.5 w-3.5 text-slate-300 opacity-0 transition-all group-hover/item:translate-x-0.5 group-hover/item:opacity-100 group-hover/item:text-brand-600" />
                    </button>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* 4. USER PROFILE */}
          <div className="relative group" ref={profileRef}>
            <button
              type="button"
              onClick={() => {
                setProfileOpen(!profileOpen);
                setDemoOpen(false);
              }}
              className={`relative flex h-10 w-10 items-center justify-center rounded-xl border transition-all duration-150 hover:-translate-y-0.5 active:translate-y-0 ${
                profileOpen
                  ? 'border-brand-400 bg-brand-50 text-brand-600 shadow-[0_2px_0_0_#38bdf8]'
                  : 'border-slate-200/90 bg-white/90 text-slate-600 hover:border-slate-300 hover:bg-slate-50 hover:text-slate-900 hover:shadow-[0_2px_0_0_#cbd5e1]'
              }`}
            >
              <User className="h-4.5 w-4.5" />
            </button>
            <NavTooltip label="ACCOUNT" hidden={profileOpen} />

            {/* PROFILE POPOVER */}
            {profileOpen && (
              <div className="absolute right-0 top-12 z-50 w-60 overflow-hidden rounded-2xl border border-slate-200/90 bg-white shadow-2xl ring-1 ring-slate-900/5 animate-in fade-in zoom-in-95 duration-150">
                <div className="border-b border-slate-100 bg-gradient-to-br from-slate-50 via-white to-brand-50/30 px-4 py-3.5">
                  <div className="flex items-center gap-3">
                    <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-gradient-to-br from-brand-500 via-sky-500 to-brand-600 text-xs font-bold text-white shadow-xs ring-2 ring-brand-100">
                      {displayName.charAt(0)}
                    </div>
                    <div className="min-w-0 flex-1">
                      <p className="flex items-center gap-1.5 truncate text-xs font-bold text-slate-800 leading-tight">
                        <span>Hi, <span className="text-brand-600">{displayName}</span></span>
                        <ShieldCheck className="h-3.5 w-3.5 text-brand-500 shrink-0" />
                      </p>
                    </div>
                  </div>
                </div>

                <div className="p-1.5 space-y-0.5">
                  <Link
                    to="/analysis"
                    onClick={() => setProfileOpen(false)}
                    className="group flex w-full items-center justify-between rounded-xl px-2.5 py-2 text-xs font-semibold text-slate-700 transition-all hover:bg-slate-50 hover:text-slate-900"
                  >
                    <div className="flex items-center gap-2.5">
                      <div className="flex h-7 w-7 items-center justify-center rounded-lg border border-slate-200/60 bg-slate-100/80 text-slate-500 transition-colors group-hover:border-brand-200 group-hover:bg-brand-50 group-hover:text-brand-600">
                        <History className="h-3.5 w-3.5" />
                      </div>
                      <span>Upload History</span>
                    </div>
                    <ArrowRight className="h-3.5 w-3.5 text-slate-300 opacity-0 transition-all group-hover:translate-x-0.5 group-hover:opacity-100 group-hover:text-brand-600" />
                  </Link>

                  <div className="my-1 border-t border-slate-100" />

                  <button
                    type="button"
                    onClick={() => {
                      setProfileOpen(false);
                      if (onLogout) onLogout();
                    }}
                    className="group flex w-full items-center gap-2.5 rounded-xl px-2.5 py-2 text-xs font-semibold text-rose-600 transition-all hover:bg-rose-50"
                  >
                    <div className="flex h-7 w-7 items-center justify-center rounded-lg border border-rose-100 bg-rose-50 text-rose-500 transition-colors group-hover:bg-rose-100 group-hover:text-rose-600">
                      <LogOut className="h-3.5 w-3.5" />
                    </div>
                    <span>Sign out</span>
                  </button>
                </div>
              </div>
            )}
          </div>

        </nav>

      </div>
    </header>
  );
}

/**
 * Custom tooltip matching the reference dark box with triangular arrow caret
 */
function NavTooltip({ label, hidden = false }) {
  if (hidden) return null;

  return (
    <div className="pointer-events-none absolute left-1/2 top-[calc(100%+8px)] -translate-x-1/2 opacity-0 group-hover:opacity-100 group-hover:translate-y-0 translate-y-1 transition-all duration-150 z-50 whitespace-nowrap">
      <div className="relative flex items-center justify-center rounded-lg border border-slate-700/90 bg-slate-900/95 px-2.5 py-1 shadow-xl backdrop-blur-sm">
        {/* Top triangular arrow pointer */}
        <div className="absolute -top-1 left-1/2 h-2 w-2 -translate-x-1/2 rotate-45 border-l border-t border-slate-700/90 bg-slate-900" />
        {/* Label text in high-contrast vibrant electric sky cyan */}
        <span className="relative z-10 text-[10px] font-bold tracking-wider text-sky-400 select-none">
          {label}
        </span>
      </div>
    </div>
  );
}