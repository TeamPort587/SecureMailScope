import React from 'react';
import { Moon, Sun } from 'lucide-react';
import { useTheme } from '../context/ThemeContext';

export default function ThemeToggle({ className = '' }) {
  const { isDark, toggleTheme } = useTheme();

  return (
    <button
      type="button"
      onClick={toggleTheme}
      className={`relative flex h-10 w-10 items-center justify-center rounded-xl border border-slate-200/90 dark:border-slate-800 bg-white/90 dark:bg-slate-900/90 text-slate-600 dark:text-slate-300 hover:border-slate-300 dark:hover:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-800 hover:text-slate-900 dark:hover:text-white transition-all duration-150 hover:-translate-y-0.5 active:translate-y-0 shadow-xs hover:shadow-[0_2px_0_0_#cbd5e1] dark:hover:shadow-[0_2px_0_0_#334155] ${className}`}
      title={isDark ? 'Switch to light mode' : 'Switch to dark mode'}
      aria-label={isDark ? 'Switch to light mode' : 'Switch to dark mode'}
    >
      {isDark ? (
        <Sun className="h-4.5 w-4.5 text-amber-400 transition-transform duration-300 hover:rotate-90" />
      ) : (
        <Moon className="h-4.5 w-4.5 text-slate-600 hover:text-slate-900 transition-transform duration-300 hover:-rotate-12" />
      )}
    </button>
  );
}
