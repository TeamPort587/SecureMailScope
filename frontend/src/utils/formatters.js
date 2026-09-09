/**
 * Formats bytes to human-readable size
 */
export function formatBytes(bytes, decimals = 2) {
  if (bytes === 0) return '0 Bytes';
  if (!bytes || isNaN(bytes)) return 'Unknown';
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

/**
 * Formats ISO timestamps into human readable dates
 */
export function formatDate(isoString) {
  if (!isoString) return '—';
  try {
    const d = new Date(isoString);
    if (isNaN(d.getTime())) return isoString;
    return new Intl.DateTimeFormat('en-US', {
      year: 'numeric',
      month: 'short',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false,
    }).format(d);
  } catch {
    return isoString;
  }
}

/**
 * Renders tri-state security values accurately preserving UNKNOWN and NOT_OBSERVABLE.
 * CRITICAL RULE: Never map UNKNOWN -> "No" or NOT_OBSERVABLE -> "Missing".
 */
export function formatTriState(value) {
  if (value === null || value === undefined) {
    return { text: 'NOT SPECIFIED', badgeClass: 'bg-slate-800 text-slate-400 border-slate-700' };
  }
  const str = String(value).toUpperCase().trim();
  if (str === 'YES' || str === 'TRUE') {
    return { text: 'YES', badgeClass: 'bg-emerald-500/25 text-emerald-200 border-emerald-500/30' };
  }
  if (str === 'NO' || str === 'FALSE') {
    return { text: 'NO', badgeClass: 'bg-slate-800 text-slate-300 border-slate-700' };
  }
  if (str === 'NOT_OBSERVABLE') {
    return { text: 'NOT OBSERVABLE', badgeClass: 'bg-purple-500/25 text-purple-200 border-purple-500/30' };
  }
  if (str === 'UNKNOWN') {
    return { text: 'UNKNOWN', badgeClass: 'bg-amber-500/25 text-amber-200 border-amber-500/30' };
  }
  return { text: str, badgeClass: 'bg-slate-800 text-slate-300 border-slate-700' };
}

/**
 * Format encryption mode with visual context
 */
export function formatEncryptionMode(mode) {
  const m = (mode || 'UNKNOWN').toUpperCase();
  switch (m) {
    case 'STARTTLS':
      return { label: 'STARTTLS', color: 'text-sky-400', badge: 'bg-sky-500/25 text-sky-200 border-sky-500/40' };
    case 'IMPLICIT_TLS':
      return { label: 'IMPLICIT TLS', color: 'text-emerald-400', badge: 'bg-emerald-500/25 text-emerald-200 border-emerald-500/40' };
    case 'PLAINTEXT':
      return { label: 'PLAINTEXT', color: 'text-rose-400', badge: 'bg-rose-500/25 text-rose-200 border-rose-500/40' };
    default:
      return { label: m, color: 'text-slate-400', badge: 'bg-slate-800 text-slate-400 border-slate-700' };
  }
}
