import React, { useState, useEffect } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { Shield, LayoutDashboard, History, Sparkles, Server, CheckCircle2, AlertCircle, LogIn, LogOut, User, Sun, Moon } from 'lucide-react';
import { DEMO_PRESETS } from '../mock/demoCaptures';
import { analysisApi } from '../api/analysisApi';
import { useAuth } from '../context/AuthContext';
import { useTheme } from '../context/ThemeContext';

<<<<<<< HEAD
export default function Navbar({ onLoadPreset, onResetAnalysis, onLogout, user }) {

  const [demoOpen, setDemoOpen] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [profileOpen, setProfileOpen] = useState(false);

  const demoRef = useRef(null);
  const profileRef = useRef(null);
=======
export default function Navbar({ onSelectPreset = null }) {
  const location = useLocation();
  const { userEmail, isAuthenticated, logout, openAuthModal } = useAuth();
  const { isDark, toggleTheme } = useTheme();
  const [gatewayStatus, setGatewayStatus] = useState('checking'); // 'online' | 'offline' | 'checking'
  const [showPresetMenu, setShowPresetMenu] = useState(false);
>>>>>>> fa4deee23e3439463fa2e7a7defb47a88ada3fbd

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
    <header className="sticky top-0 z-40 w-full border-b border-slate-200 dark:border-slate-800/80 bg-white/95 dark:bg-slate-950/80 backdrop-blur-md transition-colors">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between gap-4">
        {/* Logo & Brand */}
        <div className="flex items-center gap-6">
          <Link to="/" className="flex items-center gap-2.5 group focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-400 rounded-lg p-1">
            <div className="w-9 h-9 rounded-xl bg-gradient-to-tr from-brand-600 to-sky-400 p-0.5 shadow-lg shadow-brand-500/20 flex items-center justify-center">
              <div className="w-full h-full bg-slate-950 rounded-[10px] flex items-center justify-center group-hover:bg-slate-900 transition-colors">
                <Shield className="w-5 h-5 text-brand-400" />
              </div>
            </div>
            <div>
              <div className="flex items-center gap-1.5">
                <span className="font-bold text-base tracking-tight text-slate-900 dark:text-white">SecureMailScope</span>
                <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-brand-50 dark:bg-brand-500/10 text-brand-700 dark:text-brand-400 border border-brand-200 dark:border-brand-500/20 font-semibold">MVP</span>
              </div>
              <p className="text-[11px] text-slate-500 dark:text-slate-400 font-normal leading-none hidden sm:block">Email PCAP Security Inspector</p>
            </div>
          </Link>

          {/* Nav Links */}
          <nav className="flex items-center gap-1">
            <Link
              to="/"
              className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                location.pathname === '/' || location.pathname.startsWith('/analysis')
                  ? 'bg-brand-50 dark:bg-slate-800 text-brand-700 dark:text-brand-400 font-semibold border border-brand-200/70 dark:border-transparent shadow-sm dark:shadow-none'
                  : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-900'
              }`}
            >
              <LayoutDashboard className="w-4 h-4" />
              <span>Dashboard</span>
            </Link>

            <Link
              to="/history"
              className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                location.pathname === '/history'
                  ? 'bg-brand-50 dark:bg-slate-800 text-brand-700 dark:text-brand-400 font-semibold border border-brand-200/70 dark:border-transparent shadow-sm dark:shadow-none'
                  : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-900'
              }`}
            >
              <History className="w-4 h-4" />
              <span>Analysis History</span>
            </Link>
          </nav>
        </div>

        {/* Right Controls: Demo Selector & Gateway Badge & Auth */}
        <div className="flex items-center gap-3">
          {/* Quick Demo Scenarios Dropdown */}
          <div className="relative">
            <button
              onClick={() => setShowPresetMenu(!showPresetMenu)}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg bg-brand-50 dark:bg-brand-500/10 hover:bg-brand-100 dark:hover:bg-brand-500/20 text-brand-700 dark:text-brand-300 border border-brand-200 dark:border-brand-500/30 transition-colors shadow-sm"
              title="Load realistic sample captures for demonstration"
              aria-haspopup="true"
              aria-expanded={showPresetMenu}
            >
              <Sparkles className="w-3.5 h-3.5 text-brand-600 dark:text-brand-400" />
              <span className="hidden md:inline">Demo Scenarios</span>
              <span className="md:hidden">Demo</span>
            </button>

            {showPresetMenu && (
              <div
                className="absolute right-0 mt-2 w-80 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 shadow-2xl p-2 z-50 animate-in fade-in zoom-in-95 duration-100"
                role="menu"
              >
                <div className="px-2 py-1.5 border-b border-slate-100 dark:border-slate-800 mb-1">
                  <p className="text-xs font-semibold text-slate-800 dark:text-slate-200">Preloaded PCAP Captures</p>
                  <p className="text-[11px] text-slate-500 dark:text-slate-400">Strictly follows shared contract schemas</p>
                </div>
                <div className="space-y-1">
                  {DEMO_PRESETS.map((preset) => (
                    <button
                      key={preset.id}
                      onClick={() => {
                        if (onSelectPreset) onSelectPreset(preset.data);
                        setShowPresetMenu(false);
                      }}
                      className="w-full text-left p-2 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors flex flex-col gap-1 text-xs"
                      role="menuitem"
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-semibold text-slate-800 dark:text-slate-200">{preset.name}</span>
                        <span className={`text-[10px] px-1.5 py-0.5 rounded border font-mono ${preset.badgeClass}`}>
                          {preset.badge}
                        </span>
                      </div>
                      <span className="text-[11px] text-slate-500 dark:text-slate-400">{preset.description}</span>
                    </button>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Node Gateway Status Indicator */}
          <div
            className="flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-mono border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900/60"
            title={gatewayStatus === 'online' ? 'Connected to Node.js Gateway' : 'Gateway not detected; local mock mode active'}
          >
            <Server className="w-3 h-3 text-slate-400" />
            <span className="hidden sm:inline text-slate-500 dark:text-slate-400">Gateway:</span>
            {gatewayStatus === 'online' ? (
              <span className="flex items-center gap-1 text-emerald-600 dark:text-emerald-400 font-medium">
                <CheckCircle2 className="w-3 h-3" />
                <span>Live</span>
              </span>
            ) : gatewayStatus === 'offline' ? (
              <span className="flex items-center gap-1 text-amber-600 dark:text-amber-400 font-medium">
                <span className="w-1.5 h-1.5 rounded-full bg-amber-400 animate-pulse" />
                <span>Mock Mode</span>
              </span>
            ) : (
              <span className="text-slate-400">Checking...</span>
            )}
          </div>

          {/* Theme Toggle Button */}
          <button
            type="button"
            onClick={toggleTheme}
            className="p-1.5 rounded-lg border border-slate-200 dark:border-slate-700/60 bg-slate-50 dark:bg-slate-900/60 hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-600 dark:text-slate-300 hover:text-amber-500 dark:hover:text-amber-400 transition-all shadow-sm focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-400"
            title={isDark ? 'Switch to light theme' : 'Switch to dark theme'}
            aria-label={isDark ? 'Switch to light theme' : 'Switch to dark theme'}
          >
            {isDark ? (
              <Sun className="w-3.5 h-3.5 text-amber-400 transition-transform duration-200 hover:rotate-45" />
            ) : (
              <Moon className="w-3.5 h-3.5 text-sky-600 transition-transform duration-200 hover:-rotate-12" />
            )}
          </button>

          {/* User Account / Auth Section */}
          {isAuthenticated && userEmail ? (
            <div className="flex items-center gap-2 pl-2 border-l border-slate-200 dark:border-slate-800">
              <div 
                className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-slate-100 dark:bg-slate-800/80 border border-slate-200 dark:border-slate-700/60 text-xs text-slate-800 dark:text-slate-200"
                title={`Signed in as ${userEmail}`}
              >
                <div className="w-4 h-4 rounded-full bg-brand-100 dark:bg-brand-500/20 text-brand-700 dark:text-brand-400 flex items-center justify-center font-bold text-[10px]">
                  {userEmail[0].toUpperCase()}
                </div>
                <span className="max-w-[120px] truncate hidden sm:inline font-medium">{userEmail}</span>
              </div>
              <button
                onClick={logout}
                className="p-1.5 rounded-lg text-slate-400 hover:text-rose-600 hover:bg-rose-50 dark:hover:bg-rose-500/10 transition-colors"
                title="Sign out"
              >
                <LogOut className="w-4 h-4" />
              </button>
            </div>
          ) : (
            <button
              onClick={openAuthModal}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg bg-brand-600 hover:bg-brand-500 text-white shadow-md shadow-brand-500/20 transition-colors"
            >
              <LogIn className="w-3.5 h-3.5" />
              <span>Sign In</span>
            </button>
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