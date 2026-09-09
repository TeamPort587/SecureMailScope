import React from 'react';
import {
  ShieldAlert,
  AlertTriangle,
  AlertCircle,
  CheckCircle2,
  Info,
} from 'lucide-react';

import { getSeverityConfig } from '../utils/severity';

const SEVERITY_ICONS = {
  CRITICAL: ShieldAlert,
  HIGH: AlertTriangle,
  MEDIUM: AlertCircle,
  LOW: CheckCircle2,
  INFO: Info,
};

const SEVERITY_STYLES = {
  CRITICAL: {
    badge:
      'border-red-200 bg-red-50 text-red-700',
    icon: 'text-red-600',
  },

  HIGH: {
    badge:
      'border-orange-200 bg-orange-50 text-orange-700',
    icon: 'text-orange-600',
  },

  MEDIUM: {
    badge:
      'border-amber-200 bg-amber-50 text-amber-700',
    icon: 'text-amber-600',
  },

  LOW: {
    badge:
      'border-emerald-200 bg-emerald-50 text-emerald-700',
    icon: 'text-emerald-600',
  },

  INFO: {
    badge:
      'border-blue-200 bg-blue-50 text-blue-700',
    icon: 'text-blue-600',
  },
};

const SIZE_CONFIG = {
  sm: {
    wrapper:
      'px-2.5 py-1 rounded-lg text-[10px] gap-1.5',
    icon: 'h-3 w-3',
  },

  md: {
    wrapper:
      'px-3 py-1.5 rounded-lg text-xs gap-1.5',
    icon: 'h-3.5 w-3.5',
  },

  lg: {
    wrapper:
      'px-3.5 py-2 rounded-lg text-sm gap-2',
    icon: 'h-4 w-4',
  },
};

export default function RiskBadge({
  level,
  size = 'md',
  className = '',
}) {
  const config = getSeverityConfig(level);

  const severity = config?.label || 'INFO';

  const IconComponent =
    SEVERITY_ICONS[severity] || Info;

  const severityStyle =
    SEVERITY_STYLES[severity] ||
    SEVERITY_STYLES.INFO;

  const sizeConfig =
    SIZE_CONFIG[size] || SIZE_CONFIG.md;

  return (
    <span
      className={[
        'inline-flex items-center',
        'border',
        'font-semibold',
        'uppercase',
        'tracking-wide',
        'transition-colors duration-200',
        'select-none',
        severityStyle.badge,
        sizeConfig.wrapper,
        className,
      ]
        .filter(Boolean)
        .join(' ')}
      role="status"
      aria-label={`Risk level: ${severity}`}
    >
      <IconComponent
        className={`${sizeConfig.icon} shrink-0 ${severityStyle.icon}`}
        aria-hidden="true"
      />

      <span className="leading-none">
        {severity}
      </span>
    </span>
  );
}