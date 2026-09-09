import React, { useEffect, useRef, useState } from 'react';
import {
  ChevronDown,
  Database,
  LayoutDashboard,
  History,
  Server,
  Shield,
  Sparkles,
  Activity,
  Menu,
  X,
  FileSearch,
} from 'lucide-react';

import ThemeToggle from './ThemeToggle';
import { DEMO_PRESETS } from '../mock/demoCaptures';

export default function Navbar({
  gatewayStatus = 'mock',
  onLoadPreset,
}) {
  const [demoOpen, setDemoOpen] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);

  const demoRef = useRef(null);

  useEffect(() => {
    const handleOutsideClick = (event) => {
      if (
        demoRef.current &&
        !demoRef.current.contains(event.target)
      ) {
        setDemoOpen(false);
      }
    };

    document.addEventListener('mousedown', handleOutsideClick);

    return () => {
      document.removeEventListener(
        'mousedown',
        handleOutsideClick
      );
    };
  }, []);

  const statusConfig = {
    connected: {
      label: 'Connected',
      dot: 'bg-emerald-500',
      text: 'text-emerald-700',
    },
    mock: {
      label: 'Mock mode',
      dot: 'bg-amber-500',
      text: 'text-amber-700',
    },
    checking: {
      label: 'Checking',
      dot: 'bg-slate-400',
      text: 'text-slate-600',
    },
  };

  const status =
    statusConfig[gatewayStatus] || statusConfig.mock;

  const handlePreset = (preset) => {
    if (onLoadPreset) {
      onLoadPreset(preset.data);
    }

    setDemoOpen(false);
    setMobileOpen(false);
  };

  return (
    <>
      {/* =====================================================
          MOBILE TOP BAR
      ====================================================== */}
      <header className="sticky top-0 z-50 flex h-16 items-center justify-between border-b border-slate-200 bg-white px-4 md:hidden">
        <div className="flex items-center gap-3">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-brand-200 bg-brand-50">
            <Shield className="h-5 w-5 text-brand-600" />
          </div>

          <div>
            <p className="text-sm font-semibold text-slate-900">
              SecureMailScope
            </p>
            <p className="text-[10px] text-slate-500">
              Email Security Analysis
            </p>
          </div>
        </div>

        <button
          type="button"
          onClick={() => setMobileOpen(!mobileOpen)}
          className="flex h-9 w-9 items-center justify-center rounded-lg border border-slate-200 bg-white text-slate-600"
          aria-label="Toggle navigation"
        >
          {mobileOpen ? (
            <X className="h-4 w-4" />
          ) : (
            <Menu className="h-4 w-4" />
          )}
        </button>
      </header>

      {/* =====================================================
          MOBILE MENU
      ====================================================== */}
      {mobileOpen && (
        <div className="fixed inset-x-0 top-16 z-40 border-b border-slate-200 bg-white p-3 shadow-lg md:hidden">
          <SidebarNavigation
            gatewayStatus={status}
            onLoadPreset={handlePreset}
            demoOpen={demoOpen}
            setDemoOpen={setDemoOpen}
            demoRef={demoRef}
            mobile
          />
        </div>
      )}

      {/* =====================================================
          DESKTOP SIDEBAR
      ====================================================== */}
      <aside className="fixed inset-y-0 left-0 z-40 hidden w-[248px] flex-col border-r border-slate-200 bg-white md:flex">
        {/* Brand */}
        <div className="flex h-[76px] shrink-0 items-center border-b border-slate-100 px-5">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-brand-200 bg-brand-50">
              <Shield className="h-5 w-5 text-brand-600" />
            </div>

            <div>
              <div className="flex items-center gap-2">
                <span className="text-[15px] font-semibold tracking-tight text-slate-900">
                  SecureMailScope
                </span>

                <span className="rounded-md border border-brand-200 bg-brand-50 px-1.5 py-0.5 text-[9px] font-semibold text-brand-700">
                  MVP
                </span>
              </div>

              <p className="mt-0.5 text-[10px] text-slate-500">
                Email Security Analysis
              </p>
            </div>
          </div>
        </div>

        {/* Navigation */}
        <div className="flex flex-1 flex-col overflow-y-auto px-3 py-5">
          <SidebarNavigation
            gatewayStatus={status}
            onLoadPreset={handlePreset}
            demoOpen={demoOpen}
            setDemoOpen={setDemoOpen}
            demoRef={demoRef}
          />
        </div>

        {/* Sidebar footer */}
        <SidebarFooter />
      </aside>
    </>
  );
}

/* ===============================================================
   SIDEBAR NAVIGATION
=============================================================== */

function SidebarNavigation({
  gatewayStatus,
  onLoadPreset,
  demoOpen,
  setDemoOpen,
  demoRef,
  mobile = false,
}) {
  return (
    <div className="flex flex-col gap-6">
      {/* Analysis */}
      <div>
        <p className="mb-2 px-3 text-[10px] font-semibold uppercase tracking-[0.12em] text-slate-400">
          Analysis
        </p>

        <div className="space-y-1">
          <SidebarLink
            href="/"
            icon={<LayoutDashboard className="h-4 w-4" />}
            label="Dashboard"
            active
          />

          <SidebarLink
            href="/analysis"
            icon={<FileSearch className="h-4 w-4" />}
            label="Analysis"
          />

          <SidebarLink
            href="/history"
            icon={<History className="h-4 w-4" />}
            label="History"
          />
        </div>
      </div>

      {/* Tools */}
      <div>
        <p className="mb-2 px-3 text-[10px] font-semibold uppercase tracking-[0.12em] text-slate-400">
          Tools
        </p>

        <div className="space-y-1">
          <div className="relative" ref={demoRef}>
            <button
              type="button"
              onClick={() => setDemoOpen(!demoOpen)}
              className={`flex w-full items-center gap-3 rounded-lg px-3 py-2.5 text-left text-xs font-medium transition-colors ${
                demoOpen
                  ? 'bg-brand-50 text-brand-700'
                  : 'text-slate-600 hover:bg-slate-50 hover:text-slate-900'
              }`}
            >
              <Sparkles
                className={`h-4 w-4 ${
                  demoOpen
                    ? 'text-brand-600'
                    : 'text-slate-400'
                }`}
              />

              <span className="flex-1">
                Demo captures
              </span>

              <ChevronDown
                className={`h-3.5 w-3.5 transition-transform ${
                  demoOpen ? 'rotate-180' : ''
                }`}
              />
            </button>

            {demoOpen && (
              <div className="mt-1 overflow-hidden rounded-lg border border-slate-200 bg-slate-50">
                {DEMO_PRESETS.map((preset) => (
                  <button
                    key={preset.id}
                    type="button"
                    onClick={() => onLoadPreset(preset)}
                    className="flex w-full items-start gap-2.5 border-b border-slate-200 p-3 text-left last:border-0 hover:bg-white"
                  >
                    <Database className="mt-0.5 h-3.5 w-3.5 shrink-0 text-brand-600" />

                    <div className="min-w-0">
                      <p className="truncate text-[11px] font-semibold text-slate-800">
                        {preset.name.split(':')[1]?.trim() ||
                          preset.name}
                      </p>

                      <p className="mt-1 line-clamp-2 text-[10px] leading-4 text-slate-500">
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

      {/* System */}
      <div>
        <p className="mb-2 px-3 text-[10px] font-semibold uppercase tracking-[0.12em] text-slate-400">
          System
        </p>

        <div className="rounded-xl border border-slate-200 bg-slate-50 p-3">
          <div className="flex items-center gap-2.5">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-white">
              <Server className="h-4 w-4 text-slate-500" />
            </div>

            <div className="min-w-0">
              <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-400">
                Gateway
              </p>

              <div className="mt-1 flex items-center gap-1.5">
                <span
                  className={`h-1.5 w-1.5 rounded-full ${gatewayStatus.dot}`}
                />

                <span
                  className={`text-[11px] font-semibold ${gatewayStatus.text}`}
                >
                  {gatewayStatus.label}
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Theme */}
      <div className="mt-auto border-t border-slate-100 pt-4">
        <div className="flex items-center justify-between px-3">
          <span className="text-[11px] font-medium text-slate-500">
            Appearance
          </span>

          <ThemeToggle />
        </div>
      </div>
    </div>
  );
}

/* ===============================================================
   SIDEBAR LINK
=============================================================== */

function SidebarLink({
  href,
  icon,
  label,
  active = false,
}) {
  return (
    <a
      href={href}
      className={`relative flex items-center gap-3 rounded-lg px-3 py-2.5 text-xs font-medium transition-all ${
        active
          ? 'bg-brand-50 text-brand-700'
          : 'text-slate-600 hover:bg-slate-50 hover:text-slate-900'
      }`}
    >
      {active && (
        <span className="absolute left-0 top-1/2 h-5 w-0.5 -translate-y-1/2 rounded-full bg-brand-500" />
      )}

      <span
        className={
          active ? 'text-brand-600' : 'text-slate-400'
        }
      >
        {icon}
      </span>

      <span>{label}</span>
    </a>
  );
}

/* ===============================================================
   SIDEBAR FOOTER
=============================================================== */

function SidebarFooter() {
  return (
    <div className="border-t border-slate-100 p-4">
      <div className="rounded-xl border border-slate-200 bg-slate-50 p-3.5">
        <div className="flex items-center gap-2.5">
          <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-white">
            <Activity className="h-3.5 w-3.5 text-emerald-600" />
          </div>

          <div>
            <p className="text-[10px] font-semibold text-slate-700">
              Analysis engine
            </p>

            <div className="mt-0.5 flex items-center gap-1.5">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-500" />

              <span className="text-[9px] font-medium text-emerald-700">
                Operational
              </span>
            </div>
          </div>
        </div>

        <div className="mt-3 border-t border-slate-200 pt-3">
          <div className="flex items-center justify-between">
            <span className="text-[9px] text-slate-400">
              SecureMailScope
            </span>

            <span className="text-[9px] font-semibold text-slate-500">
              SIH 2026
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}