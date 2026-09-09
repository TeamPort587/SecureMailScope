/** @type {import('tailwindcss').Config} */

export default {
  content: [
    './index.html',
    './src/**/*.{js,ts,jsx,tsx}',
  ],

  darkMode: 'class',

  theme: {
    extend: {

      /* =========================================================
         COLORS
      ========================================================= */

      colors: {

        brand: {
          50: '#f0f9ff',
          100: '#e0f2fe',
          200: '#bae6fd',
          300: '#7dd3fc',
          400: '#38bdf8',
          500: '#0ea5e9',
          600: '#0284c7',
          700: '#0369a1',
          800: '#075985',
          900: '#0c4a6e',
          950: '#082f49',
        },

        slate: {
          850: '#151f32',
          900: '#0f172a',
          950: '#0b1120',
        },

        severity: {
          critical: '#ef4444',
          high: '#f97316',
          medium: '#f59e0b',
          low: '#ca8a04',
          info: '#3b82f6',
        },

      },


      /* =========================================================
         TYPOGRAPHY
      ========================================================= */

      fontFamily: {

        sans: [
          'Inter',
          'ui-sans-serif',
          'system-ui',
          'sans-serif',
        ],

        mono: [
          'JetBrains Mono',
          'ui-monospace',
          'SFMono-Regular',
          'monospace',
        ],

      },


      fontSize: {

        xs: [
          '0.75rem',
          {
            lineHeight: '1rem',
          },
        ],

        sm: [
          '0.8125rem',
          {
            lineHeight: '1.25rem',
          },
        ],

        base: [
          '0.875rem',
          {
            lineHeight: '1.375rem',
          },
        ],

        lg: [
          '1rem',
          {
            lineHeight: '1.5rem',
          },
        ],

        xl: [
          '1.125rem',
          {
            lineHeight: '1.625rem',
          },
        ],

        '2xl': [
          '1.375rem',
          {
            lineHeight: '1.75rem',
          },
        ],

        '3xl': [
          '1.75rem',
          {
            lineHeight: '2.125rem',
          },
        ],

      },


      /* =========================================================
         BORDER RADIUS
      ========================================================= */

      borderRadius: {

        lg: '0.625rem',

        xl: '0.875rem',

        '2xl': '1rem',

      },


      /* =========================================================
         SHADOWS
      ========================================================= */

      boxShadow: {

        'soft-light':
          '0 8px 30px rgba(15, 23, 42, 0.06)',

        'soft-card':
          '0 4px 20px rgba(15, 23, 42, 0.04)',

        'soft-hover':
          '0 12px 32px rgba(15, 23, 42, 0.08)',

        'soft-dark':
          '0 8px 30px rgba(0, 0, 0, 0.18)',

      },


      /* =========================================================
         TRANSITIONS
      ========================================================= */

      transitionTimingFunction: {

        smooth:
          'cubic-bezier(0.4, 0, 0.2, 1)',

      },

    },
  },

  plugins: [],
};