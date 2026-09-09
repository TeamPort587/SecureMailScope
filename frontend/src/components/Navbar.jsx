import React, { useEffect, useRef, useState } from 'react';

import {
  ChevronDown,
  Database,
  LayoutDashboard,
  History,
  FileSearch,
  Sparkles,
  Activity,
  Menu,
  X,
  User,
  Mail,
  LogOut,
  Settings,
} from 'lucide-react';

import { NavLink } from 'react-router-dom';

import { DEMO_PRESETS } from '../mock/demoCaptures';

export default function Navbar({ onLoadPreset, onResetAnalysis, onLogout, user }) {

  const [demoOpen, setDemoOpen] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
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
    setMobileOpen(false);
  };

  return (
    <>
      {/* MOBILE HEADER */}
      <header className="sticky top-0 z-50 flex h-16 items-center justify-between border-b border-slate-200 bg-white px-4 md:hidden">
        <BrandMark />
        <button
          type="button"
          onClick={() => setMobileOpen(!mobileOpen)}
          className="flex h-9 w-9 items-center justify-center rounded-lg border border-slate-200 text-slate-600"
        >
          {mobileOpen ? <X className="h-4 w-4" /> : <Menu className="h-4 w-4" />}
        </button>
      </header>

      {/* MOBILE MENU */}
      {mobileOpen && (
        <div className="fixed inset-x-0 top-16 z-40 border-b border-slate-200 bg-white p-3 shadow-lg md:hidden">
          <SidebarNavigation
            onLoadPreset={handlePreset}
            demoOpen={demoOpen}
            setDemoOpen={setDemoOpen}
            demoRef={demoRef}
            onNavigate={() => setMobileOpen(false)}
            onResetAnalysis={onResetAnalysis}
          />
        </div>
      )}

      {/* DESKTOP SIDEBAR */}
      <aside className="fixed inset-y-0 left-0 z-40 hidden w-[220px] flex-col border-r border-slate-100 bg-white md:flex">

        {/* BRAND */}
        <div className="flex h-[72px] shrink-0 items-center border-b border-slate-100 px-5">
          <BrandMark />
        </div>

                {/* NAV */}
        <div className="flex flex-1 flex-col overflow-y-auto px-3 py-5">
          <SidebarNavigation
            onLoadPreset={handlePreset}
            demoOpen={demoOpen}
            setDemoOpen={setDemoOpen}
            demoRef={demoRef}
            onResetAnalysis={onResetAnalysis}
          />
        </div>

        {/* PROFILE */}
        <div className="border-t border-slate-100 p-3" ref={profileRef}>
          <button
            type="button"
            onClick={() => setProfileOpen(!profileOpen)}
            className="
              group flex w-full items-center gap-3
              rounded-xl px-3 py-2.5
              transition-colors
              hover:bg-slate-50
            "
          >
            <div className="
              flex h-8 w-8 shrink-0
              items-center justify-center
              rounded-full
              bg-gradient-to-br from-brand-500 to-brand-700
              text-white
              text-xs font-bold
              shadow-sm
            ">
              {user?.email?.[0]?.toUpperCase() || 'U'}
            </div>
            <div className="min-w-0 flex-1 text-left">
              <p className="text-[12px] font-semibold text-slate-800 truncate">{user?.email?.split('@')[0] || 'User'}</p>
              <p className="text-[10px] text-slate-400 truncate">{user?.email || ''}</p>
            </div>
            <ChevronDown className={`
              h-3.5 w-3.5 text-slate-400 transition-transform shrink-0
              ${profileOpen ? 'rotate-180' : ''}
            `} />
          </button>

          {/* PROFILE POPOVER */}
          {profileOpen && (
            <div className="
              mb-2 overflow-hidden
              rounded-xl border border-slate-200
              bg-white shadow-lg
            ">
              <div className="border-b border-slate-100 px-4 py-3">
                <p className="text-[11px] font-semibold text-slate-800">{user?.email?.split('@')[0] || 'User'}</p>
                <p className="text-[10px] text-slate-400 mt-0.5">{user?.email || ''}</p>
              </div>
              <div className="p-1.5 space-y-0.5">
                {[
                  { icon: User, label: 'Profile' },
                  { icon: Settings, label: 'Settings' },
                ].map(({ icon: Icon, label }) => (
                  <button
                    key={label}
                    type="button"
                    className="
                      flex w-full items-center gap-2.5
                      rounded-lg px-3 py-2
                      text-[11px] font-medium text-slate-600
                      transition-colors hover:bg-slate-50 hover:text-slate-900
                    "
                  >
                    <Icon className="h-3.5 w-3.5 text-slate-400" />
                    {label}
                  </button>
                ))}
                <div className="my-1 border-t border-slate-100" />
                <button
                  type="button"
                  onClick={onLogout}
                  className="
                    flex w-full items-center gap-2.5
                    rounded-lg px-3 py-2
                    text-[11px] font-medium text-rose-600
                    transition-colors hover:bg-rose-50
                  "
                >
                  <LogOut className="h-3.5 w-3.5" />
                  Sign out
                </button>
              </div>
            </div>
          )}
        </div>

      </aside>
    </>
  );
}


/* ===============================================================
   BRAND MARK
=============================================================== */

function BrandMark() {
  return (
    <div className="flex items-center gap-2">

      <img
        src="/SMS.png"
        alt="SecureMailScope"
        className="h-11 w-11 shrink-0 object-contain"
      />

      <div className="flex flex-col justify-center leading-none translate-y-1">
        <p className="text-[13px] font-bold tracking-tight leading-tight">
          <span className="text-slate-900">Secure</span>
          <span className="text-brand-600">Mail</span>
          <span className="text-slate-900">Scope</span>
        </p>
        <p className="text-[10px] text-slate-400 mt-[3px]">
          Email Security Analysis
        </p>
      </div>

    </div>
  );
}


/* ===============================================================
   SIDEBAR NAVIGATION
=============================================================== */

function SidebarNavigation({
  onLoadPreset,
  demoOpen,
  setDemoOpen,
  demoRef,
  onNavigate,
  onResetAnalysis,
}) {
  return (
    <div className="flex flex-col gap-6">

      {/* ANALYSIS */}
      <div>
        <p className="mb-1.5 px-3 text-[10px] font-semibold uppercase tracking-[0.12em] text-slate-400">
          Analysis
        </p>
        <div className="space-y-0.5">
          <SidebarLink to="/" end icon={<LayoutDashboard className="h-4 w-4" />} label="Dashboard" onClick={() => { if (onResetAnalysis) onResetAnalysis(); if (onNavigate) onNavigate(); }} />
          <SidebarLink to="/analysis" icon={<FileSearch className="h-4 w-4" />} label="Analysis" onClick={onNavigate} />
        </div>
      </div>

      {/* TOOLS */}
      <div>
        <p className="mb-1.5 px-3 text-[10px] font-semibold uppercase tracking-[0.12em] text-slate-400">
          Tools
        </p>
        <div className="space-y-0.5" ref={demoRef}>
          <button
            type="button"
            onClick={() => setDemoOpen(!demoOpen)}
            className={`
              flex w-full items-center gap-3
              rounded-lg px-3 py-2.5
              text-left text-xs font-medium
              transition-colors
              ${demoOpen
                ? 'bg-brand-50 text-brand-700'
                : 'text-slate-600 hover:bg-slate-50 hover:text-slate-900'
              }
            `}
          >
            <Sparkles className={`h-4 w-4 ${demoOpen ? 'text-brand-500' : 'text-slate-400'}`} />
            <span className="flex-1">Demo Captures</span>
            <ChevronDown className={`h-3.5 w-3.5 transition-transform ${demoOpen ? 'rotate-180' : ''}`} />
          </button>

          {demoOpen && (
            <div className="mt-1 overflow-hidden rounded-xl border border-slate-200 bg-slate-50/80">
              {DEMO_PRESETS.map((preset) => (
                <button
                  key={preset.id}
                  type="button"
                  onClick={() => onLoadPreset(preset)}
                  className="flex w-full items-start gap-2.5 border-b border-slate-100 p-3 text-left transition-colors last:border-0 hover:bg-white"
                >
                  <Database className="mt-0.5 h-3.5 w-3.5 shrink-0 text-brand-500" />
                  <div className="min-w-0">
                    <p className="truncate text-[11px] font-semibold text-slate-800">
                      {preset.name.split(':')[1]?.trim() || preset.name}
                    </p>
                    <p className="mt-0.5 line-clamp-2 text-[10px] leading-4 text-slate-500">
                      {preset.description}
                    </p>
                  </div>
                </button>
              ))}
            </div>
          )}
        </div>
      </div>

    </div>
  );
}


/* ===============================================================
   SIDEBAR LINK
=============================================================== */

function SidebarLink({ to, icon, label, end = false, onClick }) {
  return (
    <NavLink
      to={to}
      end={end}
      onClick={onClick}
      className={({ isActive }) =>
        `relative flex items-center gap-3 rounded-lg px-3 py-2.5 text-xs font-medium transition-all ${isActive
          ? 'bg-brand-50 text-brand-700'
          : 'text-slate-600 hover:bg-slate-50 hover:text-slate-900'
        }`
      }
    >
      {({ isActive }) => (
        <>
          {isActive && (
            <span className="absolute left-0 top-1/2 h-5 w-0.5 -translate-y-1/2 rounded-full bg-brand-500" />
          )}
          <span className={isActive ? 'text-brand-600' : 'text-slate-400'}>
            {icon}
          </span>
          <span>{label}</span>
        </>
      )}
    </NavLink>
  );
}


/* ===============================================================
   SIDEBAR FOOTER
=============================================================== */

function SidebarFooter() {
  return (
    <div className="px-4 pb-4">
      <div className="
        flex items-center justify-between
        rounded-xl
        border border-slate-100
        bg-slate-50
        px-3 py-2.5
      ">
        <div className="flex items-center gap-2">
          <div className="flex h-6 w-6 items-center justify-center rounded-lg bg-white shadow-sm">
            <Activity className="h-3 w-3 text-yellow-500" />
          </div>
          <div>
            <p className="text-[10px] font-semibold text-slate-600">Analysis Engine</p>
            <div className="flex items-center gap-1 mt-0.5">
              <span className="h-1.5 w-1.5 rounded-full bg-yellow-500" />
              <span className="text-[9px] font-medium text-yellow-600">Operational</span>
            </div>
          </div>
        </div>
        <span className="text-[9px] font-semibold text-slate-400">SIH 2026</span>
      </div>
    </div>
  );
}