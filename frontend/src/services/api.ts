import {
  AlertDetail,
  AlertItem,
  DetectionRule,
  IncidentDetail,
  IncidentItem,
  InvestigationNote,
  OverviewDashboardData,
  SecurityEvent,
  TelemetryScenario,
  ThreatIndicator,
  UserProfile,
} from '../types';

const TOKEN_KEY = 'threatlens_auth_token';
const USER_KEY = 'threatlens_auth_user';
const API_URL_OVERRIDE_KEY = 'threatlens_api_url';

export function resolveApiBase(): string {
  try {
    const custom = localStorage.getItem(API_URL_OVERRIDE_KEY);
    if (custom && custom.trim()) {
      const clean = custom.trim().replace(/\/+$/, '');
      return clean.endsWith('/api') ? clean : `${clean}/api`;
    }
  } catch {
    // ignore
  }

  const envUrl = (import.meta.env.VITE_API_BASE_URL || '').trim();
  if (envUrl) {
    const clean = envUrl.replace(/\/+$/, '');
    return clean.endsWith('/api') ? clean : `${clean}/api`;
  }

  return '/api';
}

export function setCustomApiUrl(url: string): void {
  try {
    if (!url || !url.trim()) {
      localStorage.removeItem(API_URL_OVERRIDE_KEY);
    } else {
      localStorage.setItem(API_URL_OVERRIDE_KEY, url.trim());
    }
  } catch {
    // ignore
  }
}

export function getCustomApiUrl(): string {
  try {
    return localStorage.getItem(API_URL_OVERRIDE_KEY) || import.meta.env.VITE_API_BASE_URL || '';
  } catch {
    return import.meta.env.VITE_API_BASE_URL || '';
  }
}

export function getStoredToken(): string | null {
  try {
    return localStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}

export function setStoredAuth(token: string, user: UserProfile): void {
  try {
    localStorage.setItem(TOKEN_KEY, token);
    localStorage.setItem(USER_KEY, JSON.stringify(user));
  } catch {
    // ignore storage errors
  }
}

export function clearStoredAuth(): void {
  try {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(USER_KEY);
  } catch {
    // ignore
  }
}

export function getStoredUser(): UserProfile | null {
  try {
    const raw = localStorage.getItem(USER_KEY);
    return raw ? (JSON.parse(raw) as UserProfile) : null;
  } catch {
    return null;
  }
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const token = getStoredToken();
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...((options.headers as Record<string, string>) || {}),
  };
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const base = resolveApiBase();
  const cleanPath = path.startsWith('/') ? path : `/${path}`;
  const fullUrl = `${base}${cleanPath}`;

  const response = await fetch(fullUrl, {
    ...options,
    headers,
  });

  if (!response.ok) {
    let errDetail = `HTTP ${response.status}: ${response.statusText}`;
    try {
      const body = await response.json();
      if (body.detail) {
        errDetail = typeof body.detail === 'string' ? body.detail : JSON.stringify(body.detail);
      }
    } catch {
      // ignore json parse error
    }
    throw new Error(errDetail);
  }

  return response.json() as Promise<T>;
}

export const api = {
  // Authentication & Users
  login: async (username: string, password: string) => {
    const res = await request<{
      access_token: string;
      token_type: string;
      expires_in: number;
      user: UserProfile;
    }>('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    });
    setStoredAuth(res.access_token, res.user);
    return res;
  },

  getMe: () => request<UserProfile>('/auth/me'),
  verifyToken: () => request<any>('/auth/verify'),
  listUsers: () => request<UserProfile[]>('/auth/users'),

  // Dashboard & Analytics
  getOverviewDashboard: () => request<OverviewDashboardData>('/analytics/overview'),
  getAnalyticsPerformance: () => request<any>('/analytics/performance'),
  getDetectionAccuracy: () => request<any>('/analytics/detection-accuracy'),
  getIncidentAnalytics: () => request<any>('/analytics/incidents'),

  // Global Search
  globalSearch: (q: string) => request<any>(`/search?q=${encodeURIComponent(q)}`),

  // Security Events Explorer & Ingestion
  listEvents: (params: Record<string, any> = {}) => {
    const searchParams = new URLSearchParams();
    Object.entries(params).forEach(([k, v]) => {
      if (v !== undefined && v !== null && v !== '' && v !== 'all') {
        searchParams.set(k, String(v));
      }
    });
    return request<{
      items: SecurityEvent[];
      total: number;
      page: number;
      page_size: number;
      total_pages: number;
    }>(`/events?${searchParams.toString()}`);
  },

  getEventDetail: (eventId: string | number) =>
    request<{
      event: SecurityEvent;
      related_events: SecurityEvent[];
      linked_alerts: Array<{
        id: number;
        alert_id: string;
        title: string;
        severity: string;
        status: string;
        rule_code: string;
      }>;
    }>(`/events/${encodeURIComponent(String(eventId))}`),

  ingestEvent: (payload: Record<string, any>) =>
    request<{
      event: SecurityEvent;
      generated_alerts_count: number;
      generated_alert_ids: string[];
    }>('/events', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  // Alerts Management
  listAlerts: (params: Record<string, any> = {}) => {
    const searchParams = new URLSearchParams();
    Object.entries(params).forEach(([k, v]) => {
      if (v !== undefined && v !== null && v !== '' && v !== 'all') {
        searchParams.set(k, String(v));
      }
    });
    return request<{
      items: AlertItem[];
      total: number;
      page: number;
      page_size: number;
      total_pages: number;
    }>(`/alerts?${searchParams.toString()}`);
  },

  getAlertDetail: (alertId: string | number) =>
    request<AlertDetail>(`/alerts/${encodeURIComponent(String(alertId))}`),

  updateAlertStatus: (
    alertId: string | number,
    status: string,
    comment?: string,
    assigned_to?: string
  ) =>
    request<AlertDetail>(`/alerts/${encodeURIComponent(String(alertId))}/status`, {
      method: 'PATCH',
      body: JSON.stringify({ status, comment, assigned_to }),
    }),

  addAlertNote: (alertId: string | number, content: string, note_type = 'analyst_note') =>
    request<InvestigationNote>(`/alerts/${encodeURIComponent(String(alertId))}/notes`, {
      method: 'POST',
      body: JSON.stringify({ content, note_type }),
    }),

  // Detection Rules & MITRE ATT&CK
  listDetectionRules: () => request<DetectionRule[]>('/detections/rules'),
  updateDetectionRule: (ruleId: string | number, payload: Record<string, any>) =>
    request<DetectionRule>(`/detections/rules/${encodeURIComponent(String(ruleId))}`, {
      method: 'PATCH',
      body: JSON.stringify(payload),
    }),
  getMitreMappings: () => request<any>('/detections/mitre'),
  evaluateDetectionsNow: () =>
    request<{ evaluated_events_count: number; new_alerts_generated: number; alert_ids: string[] }>(
      '/detections/evaluate',
      { method: 'POST' }
    ),

  // Incident Investigation
  listIncidents: (params: Record<string, any> = {}) => {
    const searchParams = new URLSearchParams();
    Object.entries(params).forEach(([k, v]) => {
      if (v !== undefined && v !== null && v !== '' && v !== 'all') {
        searchParams.set(k, String(v));
      }
    });
    return request<{
      items: IncidentItem[];
      total: number;
      page: number;
      page_size: number;
      total_pages: number;
    }>(`/incidents?${searchParams.toString()}`);
  },

  getIncidentDetail: (incidentId: string | number) =>
    request<IncidentDetail>(`/incidents/${encodeURIComponent(String(incidentId))}`),

  createIncident: (payload: {
    title: string;
    severity: string;
    status?: string;
    description: string;
    assigned_analyst?: string;
    alert_ids?: Array<number | string>;
    evidence_references?: Array<Record<string, any>>;
  }) =>
    request<IncidentDetail>('/incidents', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  updateIncident: (incidentId: string | number, payload: Record<string, any>) =>
    request<IncidentDetail>(`/incidents/${encodeURIComponent(String(incidentId))}`, {
      method: 'PATCH',
      body: JSON.stringify(payload),
    }),

  updateIncidentStatus: (
    incidentId: string | number,
    payload: {
      status: string;
      comment?: string;
      assigned_analyst?: string;
      resolution_summary?: string;
    }
  ) =>
    request<IncidentDetail>(`/incidents/${encodeURIComponent(String(incidentId))}/status`, {
      method: 'PATCH',
      body: JSON.stringify(payload),
    }),

  linkAlertsToIncident: (incidentId: string | number, alert_ids: Array<number | string>) =>
    request<IncidentDetail>(`/incidents/${encodeURIComponent(String(incidentId))}/alerts`, {
      method: 'POST',
      body: JSON.stringify({ alert_ids }),
    }),

  unlinkAlertFromIncident: (incidentId: string | number, alertId: string | number) =>
    request<IncidentDetail>(
      `/incidents/${encodeURIComponent(String(incidentId))}/alerts/${encodeURIComponent(String(alertId))}`,
      { method: 'DELETE' }
    ),

  getIncidentEvidence: (incidentId: string | number) =>
    request<any>(`/incidents/${encodeURIComponent(String(incidentId))}/evidence`),

  addIncidentEvidence: (
    incidentId: string | number,
    payload: {
      type: string;
      reference?: string;
      event_id?: number | string;
      alert_id?: number | string;
      description?: string;
      note?: string;
    }
  ) =>
    request<IncidentDetail>(`/incidents/${encodeURIComponent(String(incidentId))}/evidence`, {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  getIncidentStatusHistory: (incidentId: string | number) =>
    request<any[]>(`/incidents/${encodeURIComponent(String(incidentId))}/history`),

  addIncidentNote: (
    incidentId: string | number,
    content: string,
    note_type = 'investigation_note'
  ) =>
    request<InvestigationNote>(`/incidents/${encodeURIComponent(String(incidentId))}/notes`, {
      method: 'POST',
      body: JSON.stringify({ content, note_type }),
    }),

  // Threat Intelligence
  lookupIpIntelligence: (ip: string) =>
    request<any>(`/threat-intelligence/lookup?ip=${encodeURIComponent(ip)}`),
  listSuspiciousIps: (params: Record<string, any> = {}) => {
    const searchParams = new URLSearchParams();
    Object.entries(params).forEach(([k, v]) => {
      if (v !== undefined && v !== null && v !== '' && v !== 'all') {
        searchParams.set(k, String(v));
      }
    });
    return request<any[]>(`/threat-intelligence/suspicious-ips?${searchParams.toString()}`);
  },
  listThreatIndicators: (params: Record<string, any> = {}) => {
    const searchParams = new URLSearchParams();
    Object.entries(params).forEach(([k, v]) => {
      if (v !== undefined && v !== null && v !== '' && v !== 'all') {
        searchParams.set(k, String(v));
      }
    });
    return request<ThreatIndicator[]>(`/threat-intelligence/indicators?${searchParams.toString()}`);
  },
  createThreatIndicator: (payload: Record<string, any>) =>
    request<ThreatIndicator>('/threat-intelligence/indicators', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  updateThreatIndicator: (id: number, payload: Record<string, any>) =>
    request<ThreatIndicator>(`/threat-intelligence/indicators/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(payload),
    }),
  deleteThreatIndicator: (id: number) =>
    request<{ deleted: boolean; indicator_value: string }>(`/threat-intelligence/indicators/${id}`, {
      method: 'DELETE',
    }),
  getThreatIntelProviders: () => request<any>('/threat-intelligence/providers'),
  updateThreatIntelProviders: (payload: Record<string, any>) =>
    request<any>('/threat-intelligence/providers', {
      method: 'PUT',
      body: JSON.stringify(payload),
    }),

  // System & Synthetic Telemetry Simulation
  getSystemHealth: () => request<any>('/system/health'),
  pollRealtimeUpdates: (since_seq = 0) =>
    request<any>(`/system/realtime/poll?since_seq=${since_seq}`),
  getAuditLogs: (
    limitOrParams: number | Record<string, any> = 60
  ) => {
    if (typeof limitOrParams === 'number') {
      return request<any[]>(`/system/audit-logs?limit=${limitOrParams}`);
    }
    const searchParams = new URLSearchParams();
    Object.entries(limitOrParams).forEach(([k, v]) => {
      if (v !== undefined && v !== null && v !== '' && v !== 'all') {
        searchParams.set(k, String(v));
      }
    });
    return request<any[]>(`/system/audit-logs?${searchParams.toString()}`);
  },
  listTelemetryScenarios: () => request<TelemetryScenario[]>('/system/scenarios'),
  simulateScenario: (scenario_id: string, volume_multiplier = 1) =>
    request<{
      scenario_id: string;
      simulated_at: string;
      accepted_count: number;
      generated_alerts_count: number;
      generated_alert_ids: string[];
    }>('/system/simulate', {
      method: 'POST',
      body: JSON.stringify({ scenario_id, volume_multiplier }),
    }),
  resetDemoEnvironment: () =>
    request<{ status: string; timestamp: string }>('/system/reset-demo', {
      method: 'POST',
    }),

  // Report Download URLs
  getCsvReportUrl: () => `${resolveApiBase()}/reports/export/csv`,
  getPdfReportUrl: () => `${resolveApiBase()}/reports/export/pdf`,
  getIncidentReport: (incidentId: string | number) =>
    request<any>(`/reports/incidents/${encodeURIComponent(String(incidentId))}`),
  getIncidentCsvReportUrl: (incidentId: string | number) =>
    `${resolveApiBase()}/reports/incidents/${encodeURIComponent(String(incidentId))}/csv`,
  getIncidentPdfReportUrl: (incidentId: string | number) =>
    `${resolveApiBase()}/reports/incidents/${encodeURIComponent(String(incidentId))}/pdf`,
};

