import React from 'react';
import { AlertCircle, AlertTriangle, CheckCircle, ShieldCheck, EyeOff, HelpCircle } from 'lucide-react';

const STATUS_CONFIGS = {
  PREFERRED: {
    label: 'Preferred',
    bg: 'bg-emerald-50 dark:bg-emerald-950/40',
    border: 'border-emerald-200 dark:border-emerald-800',
    text: 'text-emerald-700 dark:text-emerald-400',
    icon: ShieldCheck,
  },
  RECOMMENDED: {
    label: 'Recommended',
    bg: 'bg-emerald-50 dark:bg-emerald-950/40',
    border: 'border-emerald-200 dark:border-emerald-800',
    text: 'text-emerald-700 dark:text-emerald-400',
    icon: CheckCircle,
  },
  ACCEPTABLE: {
    label: 'Acceptable',
    bg: 'bg-sky-50 dark:bg-sky-950/40',
    border: 'border-sky-200 dark:border-sky-800',
    text: 'text-sky-700 dark:text-sky-400',
    icon: CheckCircle,
  },
  NOT_RECOMMENDED: {
    label: 'Not Recommended',
    bg: 'bg-amber-50 dark:bg-amber-950/40',
    border: 'border-amber-200 dark:border-amber-800',
    text: 'text-amber-700 dark:text-amber-400',
    icon: AlertTriangle,
  },
  DEPRECATED: {
    label: 'Deprecated',
    bg: 'bg-rose-50 dark:bg-rose-950/40',
    border: 'border-rose-200 dark:border-rose-800',
    text: 'text-rose-700 dark:text-rose-400',
    icon: AlertCircle,
  },
  NOT_OBSERVABLE: {
    label: 'Not Observable',
    bg: 'bg-purple-50 dark:bg-purple-950/40',
    border: 'border-purple-200 dark:border-purple-800',
    text: 'text-purple-700 dark:text-purple-400',
    icon: EyeOff,
  },
  UNKNOWN: {
    label: 'Unknown',
    bg: 'bg-slate-100 dark:bg-slate-800',
    border: 'border-slate-300 dark:border-slate-700',
    text: 'text-slate-600 dark:text-slate-400',
    icon: HelpCircle,
  },
};

export default function StandardsBadge({ status, size = 'md', showIcon = true }) {
  const normStatus = (status || 'UNKNOWN').toUpperCase();
  const config = STATUS_CONFIGS[normStatus] || STATUS_CONFIGS.UNKNOWN;
  const Icon = config.icon;

  const sizeClasses = size === 'sm'
    ? 'px-2 py-0.5 text-[10px] gap-1'
    : 'px-2.5 py-1 text-xs gap-1.5 font-semibold';

  return (
    <span
      className={`inline-flex items-center rounded-lg border font-mono tracking-tight transition-colors ${config.bg} ${config.border} ${config.text} ${sizeClasses}`}
    >
      {showIcon && <Icon className={size === 'sm' ? 'h-3 w-3 shrink-0' : 'h-3.5 w-3.5 shrink-0'} />}
      <span>{config.label}</span>
    </span>
  );
}
