import React from 'react';
import {
  alertStatusBadgeClass,
  incidentStatusBadgeClass,
  severityBadgeClass,
} from '../utils/formatters';

export const SeverityBadge: React.FC<{ severity?: string | null }> = ({ severity }) => {
  const label = (severity || 'low').toUpperCase();
  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded text-[11px] font-semibold tracking-wider border ${severityBadgeClass(
        severity
      )}`}
    >
      {label}
    </span>
  );
};

export const AlertStatusBadge: React.FC<{ status?: string | null }> = ({ status }) => {
  return (
    <span
      className={`inline-flex items-center px-2.5 py-0.5 rounded text-xs font-medium border ${alertStatusBadgeClass(
        status
      )}`}
    >
      {status || 'New'}
    </span>
  );
};

export const IncidentStatusBadge: React.FC<{ status?: string | null }> = ({ status }) => {
  return (
    <span
      className={`inline-flex items-center px-2.5 py-0.5 rounded text-xs font-medium border ${incidentStatusBadgeClass(
        status
      )}`}
    >
      {status || 'Open'}
    </span>
  );
};

