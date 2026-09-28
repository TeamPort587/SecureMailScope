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
import { useTheme } from '../context/ThemeContext';
import ThemeToggle from './ThemeToggle';

export default function Navbar({ onLoadPreset, onResetAnalysis, onLogout, user }) {
  const [demoOpen, setDemoOpen] = useState(false);
  const [profileOpen, setProfileOpen] = useState(false);
  const [isScrolled, setIsScrolled] = useState(false);

  const demoRef = useRef(null);
  const profileRef = useRef(null);

  const { isDark } = useTheme();

  // Throttled scroll listener with requestAnimationFrame and hysteresis to eliminate jitter
  useEffect(() => {
    let ticking = false;
    const handleScroll = () => {
      if (!ticking) {
        window.requestAnimationFrame(() => {
          const y = window.scrollY;
          setIsScrolled((prev) => {
            const next = prev ? y > 8 : y > 20;
            return prev !== next ? next : prev;
          });
          ticking = false;
        });
        ticking = true;
      }
    };

    handleScroll();
    window.addEventListener('scroll', handleScroll, { passive: true });
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

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

  // Dynamic button styling with hardware-accelerated transitions
  const btnClass = (isActive) =>
    `relative flex items-center justify-center rounded-xl border transition-[width,height,background-color,border-color,color,box-shadow,transform] duration-250 ease-out hover:-translate-y-0.5 active:translate-y-0 ${
      isScrolled ? 'h-8.5 w-8.5 sm:h-9 sm:w-9' : 'h-10 w-10'
    } ${
      isActive
        ? 'border-brand-400 dark:border-brand-500 bg-brand-50 dark:bg-brand-950/60 text-brand-600 dark:text-brand-400 shadow-[0_2px_0_0_#38bdf8]'
        : 'border-slate-200/90 dark:border-slate-800 bg-white/90 dark:bg-slate-900/90 text-slate-600 dark:text-slate-300 hover:border-slate-300 dark:hover:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-800 hover:text-slate-900 dark:hover:text-white hover:shadow-[0_2px_0_0_#cbd5e1] dark:hover:shadow-[0_2px_0_0_#334155]'
    }`;

  const iconClass = `${isScrolled ? 'h-4 w-4' : 'h-4.5 w-4.5'} transition-all duration-200 ease-out`;

  return (
    <header
      className={`sticky top-0 z-50 w-full h-16 sm:h-18 flex items-center justify-center border-0 border-none transition-colors duration-250 ease-out px-3 sm:px-6 pointer-events-none ${
        isScrolled
          ? 'bg-transparent'
          : 'bg-slate-50 dark:bg-slate-950'
      }`}
    >
      <div
        className={`flex items-center justify-between border transform-gpu will-change-[width,max-width,height,border-radius,background-color,box-shadow] transition-[width,max-width,height,border-radius,background-color,border-color,box-shadow,padding] duration-250 ease-out ${
          isScrolled
            ? 'pointer-events-auto w-[95%] sm:w-[88%] lg:w-[76%] max-w-5xl h-12 sm:h-13 rounded-full border-slate-200/90 dark:border-slate-800 bg-white/90 dark:bg-slate-900/90 backdrop-blur-md shadow-lg dark:shadow-[0_8px_30px_rgba(0,0,0,0.45)] px-3.5 sm:px-5'
            : 'pointer-events-auto w-full max-w-7xl h-full rounded-none border-transparent dark:border-transparent bg-transparent dark:bg-transparent px-4 sm:px-6 lg:px-8 shadow-none'
        }`}
      >
        
        {/* LEFT: BRAND LOGO */}
        <Link
          to="/"
          onClick={onResetAnalysis}
          className="group flex items-center gap-2.5 sm:gap-3 transition-opacity hover:opacity-95"
        >
          <img
            src="/SMS.png"
            alt="SecureMailScope"
            className={`shrink-0 object-contain drop-shadow-sm transform-gpu transition-all duration-250 ease-out group-hover:scale-105 ${
              isScrolled ? 'h-8 w-8 sm:h-8.5 sm:w-8.5' : 'h-9.5 w-9.5 sm:h-10 sm:w-10'
            }`}
          />
          <div className="flex flex-col justify-center">
            <span className="font-extrabold tracking-tight leading-tight text-slate-900 dark:text-slate-100 text-base sm:text-lg transition-colors duration-250 ease-out">
              Secure<span className="text-brand-600 dark:text-brand-400">Mail</span>Scope
            </span>
            <span
              className={`font-medium text-slate-500 dark:text-slate-400 tracking-tight leading-none text-xs transition-all duration-200 ease-out ${
                isScrolled
                  ? 'opacity-0 h-0 overflow-hidden'
                  : 'opacity-100 h-auto mt-0.5'
              }`}
            >
              Email Security Analysis
            </span>
          </div>
        </Link>

        {/* RIGHT: ICON BUTTON GROUP WITH HOVER TOOLTIPS */}
        <nav className="flex items-center gap-2 sm:gap-2.5">
          
          {/* 1. UPLOAD PCAP / DASHBOARD */}
          <div className="relative group">
            <NavLink
              to="/"
              end
              onClick={onResetAnalysis}
              className={({ isActive }) => btnClass(isActive)}
            >
              <FileUp className={iconClass} />
            </NavLink>
            <NavTooltip label="UPLOAD" />
          </div>

          {/* 2. ANALYSIS CENTER */}
          <div className="relative group">
            <NavLink
              to="/analysis"
              className={({ isActive }) => btnClass(isActive)}
            >
              <FileSearch className={iconClass} />
            </NavLink>
            <NavTooltip label="ANALYSIS" />
          </div>

          {/* 3. DEMO CAPTURES */}
          <div className="relative group" ref={demoRef}>
            <button
              type="button"
              aria-label="Demo Captures"
              title="Demo Captures"
              onClick={() => {
                setDemoOpen(!demoOpen);
                setProfileOpen(false);
              }}
              className={btnClass(demoOpen)}
            >
              <FlaskConical className={iconClass} />
            </button>
            <NavTooltip label="DEMO" hidden={demoOpen} />

            {/* DEMO POPOVER */}
            {demoOpen && (
              <div className="absolute right-0 top-[calc(100%+8px)] z-50 w-80 overflow-hidden rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 shadow-xl animate-in fade-in zoom-in-95 duration-150">
                <div className="border-b border-slate-100 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-850 px-4 py-3">
                  <div className="flex items-center gap-2">
                    <FlaskConical className="h-4 w-4 text-brand-600 dark:text-brand-400" />
                    <p className="text-xs font-semibold text-slate-900 dark:text-slate-100">Demo PCAP Captures</p>
                  </div>
                  <p className="text-[10px] text-slate-500 dark:text-slate-400 mt-0.5">
                    Inspect realistic email security traffic captures
                  </p>
                </div>

                <div className="max-h-[320px] overflow-y-auto p-2 space-y-1">
                  {DEMO_PRESETS.map((preset) => (
                    <button
                      key={preset.id}
                      type="button"
                      onClick={() => handlePreset(preset)}
                      className="group/item flex w-full items-start gap-2.5 rounded-xl p-2.5 text-left transition-colors hover:bg-brand-50/60 dark:hover:bg-slate-800/60"
                    >
                      <div className="mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-lg border border-brand-100 dark:border-brand-900/60 bg-brand-50 dark:bg-brand-950/60 text-brand-600 dark:text-brand-400 transition-colors group-hover/item:bg-brand-100 dark:group-hover/item:bg-brand-900/80">
                        <Database className="h-3.5 w-3.5" />
                      </div>
                      <div className="min-w-0 flex-1">
                        <p className="truncate text-xs font-semibold text-slate-800 dark:text-slate-200 group-hover/item:text-brand-700 dark:group-hover/item:text-brand-400">
                          {preset.name.split(':')[1]?.trim() || preset.name}
                        </p>
                        <p className="mt-0.5 line-clamp-2 text-[10px] leading-4 text-slate-500 dark:text-slate-400">
                          {preset.description}
                        </p>
                      </div>
                      <ArrowRight className="mt-1 h-3.5 w-3.5 text-slate-300 dark:text-slate-600 opacity-0 transition-all group-hover/item:translate-x-0.5 group-hover/item:opacity-100 group-hover/item:text-brand-600 dark:group-hover/item:text-brand-400" />
                    </button>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* 4. THEME TOGGLE (DARK / LIGHT MODE) */}
          <div className="relative group">
            <ThemeToggle
              className={btnClass(false)}
              iconClassName={iconClass}
            />
            <NavTooltip label={isDark ? 'LIGHT' : 'DARK'} />
          </div>

          {/* 5. USER PROFILE */}
          <div className="relative group" ref={profileRef}>
            <button
              type="button"
              aria-label="User Account"
              title="User Account"
              onClick={() => {
                setProfileOpen(!profileOpen);
                setDemoOpen(false);
              }}
              className={btnClass(profileOpen)}
            >
              <User className={iconClass} />
            </button>
            <NavTooltip label="ACCOUNT" hidden={profileOpen} />

            {/* PROFILE POPOVER */}
            {profileOpen && (
              <div className="absolute right-0 top-[calc(100%+8px)] z-50 w-60 overflow-hidden rounded-2xl border border-slate-200/90 dark:border-slate-800 bg-white dark:bg-slate-900 shadow-2xl ring-1 ring-slate-900/5 animate-in fade-in zoom-in-95 duration-150">
                <div className="border-b border-slate-100 dark:border-slate-800 bg-gradient-to-br from-slate-50 via-white to-brand-50/30 dark:from-slate-850 dark:via-slate-900 dark:to-brand-950/20 px-4 py-3.5">
                  <div className="flex items-center gap-3">
                    <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-gradient-to-br from-brand-500 via-sky-500 to-brand-600 text-xs font-bold text-white shadow-xs ring-2 ring-brand-100 dark:ring-brand-900/50">
                      {displayName.charAt(0)}
                    </div>
                    <div className="min-w-0 flex-1">
                      <p className="flex items-center gap-1.5 truncate text-xs font-bold text-slate-800 dark:text-slate-200 leading-tight">
                        <span>Hi, <span className="text-brand-600 dark:text-brand-400">{displayName}</span></span>
                        <ShieldCheck className="h-3.5 w-3.5 text-brand-500 shrink-0" />
                      </p>
                    </div>
                  </div>
                </div>

                <div className="p-1.5 space-y-0.5">
                  <Link
                    to="/analysis"
                    onClick={() => setProfileOpen(false)}
                    className="group flex w-full items-center justify-between rounded-xl px-2.5 py-2 text-xs font-semibold text-slate-700 dark:text-slate-300 transition-all hover:bg-slate-50 dark:hover:bg-slate-800 hover:text-slate-900 dark:hover:text-white"
                  >
                    <div className="flex items-center gap-2.5">
                      <div className="flex h-7 w-7 items-center justify-center rounded-lg border border-slate-200/60 dark:border-slate-700 bg-slate-100/80 dark:bg-slate-800 text-slate-500 dark:text-slate-400 transition-colors group-hover:border-brand-200 dark:group-hover:border-brand-800 group-hover:bg-brand-50 dark:group-hover:bg-brand-950/60 group-hover:text-brand-600 dark:group-hover:text-brand-400">
                        <History className="h-3.5 w-3.5" />
                      </div>
                      <span>Upload History</span>
                    </div>
                    <ArrowRight className="h-3.5 w-3.5 text-slate-300 dark:text-slate-600 opacity-0 transition-all group-hover:translate-x-0.5 group-hover:opacity-100 group-hover:text-brand-600 dark:group-hover:text-brand-400" />
                  </Link>

                  <div className="my-1 border-t border-slate-100 dark:border-slate-800" />

                  <button
                    type="button"
                    onClick={() => {
                      setProfileOpen(false);
                      if (onLogout) onLogout();
                    }}
                    className="group flex w-full items-center gap-2.5 rounded-xl px-2.5 py-2 text-xs font-semibold text-rose-600 dark:text-rose-400 transition-all hover:bg-rose-50 dark:hover:bg-rose-950/40"
                  >
                    <div className="flex h-7 w-7 items-center justify-center rounded-lg border border-rose-100 dark:border-rose-900/60 bg-rose-50 dark:bg-rose-950/60 text-rose-500 dark:text-rose-400 transition-colors group-hover:bg-rose-100 dark:group-hover:bg-rose-900/80 group-hover:text-rose-600 dark:group-hover:text-rose-300">
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
      <div className="relative flex items-center justify-center rounded-lg border border-slate-700/90 dark:border-slate-600 bg-slate-900/95 dark:bg-slate-850 px-2.5 py-1 shadow-xl backdrop-blur-sm">
        {/* Top triangular arrow pointer */}
        <div className="absolute -top-1 left-1/2 h-2 w-2 -translate-x-1/2 rotate-45 border-l border-t border-slate-700/90 dark:border-slate-600 bg-slate-900 dark:bg-slate-850" />
        {/* Label text in high-contrast vibrant electric sky cyan */}
        <span className="relative z-10 text-[10px] font-bold tracking-wider text-sky-400 select-none">
          {label}
        </span>
      </div>
    </div>
  );
}