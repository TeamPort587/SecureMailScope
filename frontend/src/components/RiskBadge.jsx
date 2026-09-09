import React from 'react';
import { getSeverityConfig } from '../utils/severity';
import { ShieldAlert, AlertTriangle, AlertCircle, CheckCircle, Info } from 'lucide-react';

const SEVERITY_ICONS = {
  CRITICAL: ShieldAlert,
  HIGH: AlertTriangle,
  MEDIUM: AlertCircle,
  LOW: CheckCircle,
  INFO: Info,
};

export default function RiskBadge({ level, size = 'md', className = '' }) {
  const config = getSeverityConfig(level);
  const IconComponent = SEVERITY_ICONS[config.label] || Info;

  const sizeClasses = {
    sm: 'px-2 py-0.5 text-xs gap-1',
    md: 'px-2.5 py-1 text-xs gap-1.5 font-medium',
    lg: 'px-3 py-1.5 text-sm gap-2 font-semibold',
  }[size] || 'px-2.5 py-1 text-xs gap-1.5';

  return (
    <span
      className={`inline-flex items-center rounded-full border tracking-wide uppercase font-mono ${config.badge} ${sizeClasses} ${className}`}
      role="status"
      aria-label={`Risk level: ${config.label}`}
    >
      <IconComponent className={size === 'sm' ? 'w-3 h-3' : size === 'lg' ? 'w-4 h-4' : 'w-3.5 h-3.5'} aria-hidden="true" />
      <span>{config.label}</span>
    </span>
  );
}
