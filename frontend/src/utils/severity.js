/**
 * Canonical severity indicators for SecureMailScope.
 * Color is NEVER used alone; icons and explicit text are always paired.
 */
export const SEVERITY_LEVELS = {
  CRITICAL: {
    label: 'CRITICAL',
    rank: 5,
    bg: 'bg-red-500/15',
    border: 'border-red-500/40',
    text: 'text-red-400',
    badge: 'bg-red-500/20 text-red-300 border-red-500/40',
    indicator: 'bg-red-500',
    description: 'Immediate compromise risk or clear unencrypted credential transmission.',
  },
  HIGH: {
    label: 'HIGH',
    rank: 4,
    bg: 'bg-orange-500/15',
    border: 'border-orange-500/40',
    text: 'text-orange-400',
    badge: 'bg-orange-500/20 text-orange-300 border-orange-500/40',
    indicator: 'bg-orange-500',
    description: 'Severe protocol downgrade or failed encryption upgrade.',
  },
  MEDIUM: {
    label: 'MEDIUM',
    rank: 3,
    bg: 'bg-amber-500/15',
    border: 'border-amber-500/40',
    text: 'text-amber-400',
    badge: 'bg-amber-500/20 text-amber-300 border-amber-500/40',
    indicator: 'bg-amber-500',
    description: 'Suboptimal cryptographic cipher or legacy configuration.',
  },
  LOW: {
    label: 'LOW',
    rank: 2,
    bg: 'bg-emerald-500/15',
    border: 'border-emerald-500/40',
    text: 'text-emerald-400',
    badge: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40',
    indicator: 'bg-emerald-500',
    description: 'Minor concern; connection meets standard baseline.',
  },
  INFO: {
    label: 'INFO',
    rank: 1,
    bg: 'bg-blue-500/15',
    border: 'border-blue-500/40',
    text: 'text-blue-400',
    badge: 'bg-blue-500/20 text-blue-300 border-blue-500/40',
    indicator: 'bg-blue-500',
    description: 'Informational observation, modern cipher or forward secrecy verified.',
  },
};

export function getSeverityConfig(severity) {
  const normalized = (severity || 'INFO').toUpperCase();
  return SEVERITY_LEVELS[normalized] || SEVERITY_LEVELS.INFO;
}

export function compareSeverity(a, b) {
  const rankA = getSeverityConfig(a).rank;
  const rankB = getSeverityConfig(b).rank;
  return rankB - rankA; // descending: CRITICAL first
}
