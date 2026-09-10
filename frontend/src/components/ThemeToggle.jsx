import React, { useState, useEffect } from 'react';
import { Moon, Sun } from 'lucide-react';

export default function ThemeToggle() {
  const [isDark, setIsDark] = useState(() => {
    if (typeof window !== 'undefined') {
      return document.documentElement.classList.contains('dark');
    }
    return true;
  });

  useEffect(() => {
    if (isDark) {
      document.documentElement.classList.add('dark');
      localStorage.setItem('sms_theme', 'dark');
    } else {
      document.documentElement.classList.remove('dark');
      localStorage.setItem('sms_theme', 'light');
    }
  }, [isDark]);

  // Restore saved preference on mount
  useEffect(() => {
    const saved = localStorage.getItem('sms_theme');
    if (saved === 'light') {
      setIsDark(false);
    }
  }, []);

  return (
    <button
      onClick={() => setIsDark((prev) => !prev)}
      className="relative w-9 h-9 rounded-lg border border-slate-700 dark:border-slate-700 bg-slate-200 dark:bg-slate-900 flex items-center justify-center text-amber-500 dark:text-slate-400 hover:text-amber-600 dark:hover:text-slate-200 transition-colors"
      title={isDark ? 'Switch to light mode' : 'Switch to dark mode'}
      aria-label={isDark ? 'Switch to light mode' : 'Switch to dark mode'}
    >
      {isDark ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
    </button>
  );
}
