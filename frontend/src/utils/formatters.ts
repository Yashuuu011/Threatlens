import { SeverityLevel } from '../types';

export function formatTimestamp(iso?: string | null): string {
  if (!iso) return '—';
  try {
    const d = new Date(iso);
    if (isNaN(d.getTime())) return iso;
    return d.toISOString().replace('T', ' ').substring(0, 19) + ' UTC';
  } catch {
    return iso;
  }
}

export function formatShortTime(iso?: string | null): string {
  if (!iso) return '—';
  try {
    const d = new Date(iso);
    if (isNaN(d.getTime())) return iso;
    return d.toISOString().substring(11, 19) + ' UTC';
  } catch {
    return iso;
  }
}

export function severityBadgeClass(severity?: string | null): string {
  const s = (severity || 'low').toLowerCase() as SeverityLevel;
  switch (s) {
    case 'critical':
      return 'bg-red-500/15 text-red-400 border-red-500/40';
    case 'high':
      return 'bg-orange-500/15 text-orange-400 border-orange-500/40';
    case 'medium':
      return 'bg-yellow-500/15 text-yellow-300 border-yellow-500/40';
    case 'low':
      return 'bg-cyan-500/15 text-cyan-300 border-cyan-500/40';
    default:
      return 'bg-slate-500/15 text-slate-300 border-slate-500/40';
  }
}

export function alertStatusBadgeClass(status?: string | null): string {
  switch (status) {
    case 'New':
      return 'bg-red-500/15 text-red-300 border-red-500/30';
    case 'Acknowledged':
      return 'bg-yellow-500/15 text-yellow-300 border-yellow-500/30';
    case 'Investigating':
      return 'bg-blue-500/15 text-blue-300 border-blue-500/30';
    case 'Resolved':
      return 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30';
    case 'False Positive':
      return 'bg-slate-600/20 text-slate-400 border-slate-600/40';
    default:
      return 'bg-slate-500/15 text-slate-300 border-slate-500/30';
  }
}

export function incidentStatusBadgeClass(status?: string | null): string {
  switch (status) {
    case 'Open':
      return 'bg-red-500/15 text-red-300 border-red-500/30';
    case 'Investigating':
      return 'bg-orange-500/15 text-orange-300 border-orange-500/30';
    case 'Contained':
      return 'bg-cyan-500/15 text-cyan-300 border-cyan-500/30';
    case 'Resolved':
    case 'Closed':
      return 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30';
    default:
      return 'bg-slate-500/15 text-slate-300 border-slate-500/30';
  }
}

