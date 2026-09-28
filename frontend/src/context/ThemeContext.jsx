import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';

const ThemeContext = createContext(null);

export function ThemeProvider({ children }) {
  const [theme, setThemeState] = useState(() => {
    if (typeof window !== 'undefined') {
      const saved = localStorage.getItem('sms_theme');
      if (saved === 'dark' || saved === 'light') return saved;
      return 'light';
    }
    return 'light';
  });

  useEffect(() => {
    const root = document.documentElement;
    if (theme === 'dark') {
      root.classList.add('dark');
      root.classList.remove('light');
    } else {
      root.classList.remove('dark');
      root.classList.add('light');
    }
    try {
      localStorage.setItem('sms_theme', theme);
    } catch (e) {}
  }, [theme]);

  const toggleTheme = useCallback(() => {
    setThemeState((prev) => (prev === 'dark' ? 'light' : 'dark'));
  }, []);

  const setTheme = useCallback((newTheme) => {
    if (newTheme === 'dark' || newTheme === 'light') {
      setThemeState(newTheme);
    }
  }, []);

  const value = {
    theme,
    isDark: theme === 'dark',
    toggleTheme,
    setTheme,
  };

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}

export function useTheme() {
  const context = useContext(ThemeContext);
  if (!context) {
    const isDark = typeof document !== 'undefined' && document.documentElement.classList.contains('dark');
    return {
      theme: isDark ? 'dark' : 'light',
      isDark,
      toggleTheme: () => {
        if (typeof document !== 'undefined') {
          const root = document.documentElement;
          const next = !root.classList.contains('dark');
          root.classList.toggle('dark', next);
          try {
            localStorage.setItem('sms_theme', next ? 'dark' : 'light');
          } catch (e) {}
        }
      },
      setTheme: (t) => {
        if (typeof document !== 'undefined') {
          const root = document.documentElement;
          root.classList.toggle('dark', t === 'dark');
          try {
            localStorage.setItem('sms_theme', t);
          } catch (e) {}
        }
      },
    };
  }
  return context;
}
