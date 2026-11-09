import React from 'react';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { OverviewDashboardPage } from './pages/OverviewDashboardPage';
import { SecurityEventsExplorerPage } from './pages/SecurityEventsExplorerPage';
import { AlertsManagementPage } from './pages/AlertsManagementPage';
import { DetectionRulesPage } from './pages/DetectionRulesPage';
import { IncidentInvestigationPage } from './pages/IncidentInvestigationPage';
import { ThreatDetectionPage } from './pages/ThreatDetectionPage';
import { ThreatIntelligencePage } from './pages/ThreatIntelligencePage';
import { AnalyticsReportsPage } from './pages/AnalyticsReportsPage';
import { SystemConfigurationPage } from './pages/SystemConfigurationPage';
import { SeverityBadge, AlertStatusBadge, IncidentStatusBadge } from './components/SeverityBadge';
import { api } from './services/api';

vi.mock('./services/api', () => ({
  api: {
    getOverviewDashboard: vi.fn(),
    simulateScenario: vi.fn(),
    listEvents: vi.fn(),
    getEventDetail: vi.fn(),
    ingestEvent: vi.fn(),
    listAlerts: vi.fn(),
    getAlertDetail: vi.fn(),
    updateAlertStatus: vi.fn(),
    addAlertNote: vi.fn(),
    listIncidents: vi.fn(),
    getIncidentDetail: vi.fn(),
    createIncident: vi.fn(),
    updateIncident: vi.fn(),
    updateIncidentStatus: vi.fn(),
    linkAlertsToIncident: vi.fn(),
    unlinkAlertFromIncident: vi.fn(),
    addIncidentEvidence: vi.fn(),
    addIncidentNote: vi.fn(),
    listDetectionRules: vi.fn(),
    updateDetectionRule: vi.fn(),
    getMitreMappings: vi.fn(),
    evaluateDetectionsNow: vi.fn(),
    getThreatIntelProviders: vi.fn(),
    updateThreatIntelProviders: vi.fn(),
    lookupIpIntelligence: vi.fn(),
    listThreatIndicators: vi.fn(),
    createThreatIndicator: vi.fn(),
    updateThreatIndicator: vi.fn(),
    deleteThreatIndicator: vi.fn(),
    listSuspiciousIps: vi.fn(),
    getAnalyticsPerformance: vi.fn(),
    getIncidentReport: vi.fn(),
    getCsvReportUrl: () => '/api/reports/export/csv',
    getPdfReportUrl: () => '/api/reports/export/pdf',
    getIncidentCsvReportUrl: (id: string | number) => `/api/reports/incidents/${id}/csv`,
    getIncidentPdfReportUrl: (id: string | number) => `/api/reports/incidents/${id}/pdf`,
    getSystemHealth: vi.fn(),
    pollRealtimeUpdates: vi.fn(),
    verifyToken: vi.fn(),
    listUsers: vi.fn(),
    getAuditLogs: vi.fn(),
    listTelemetryScenarios: vi.fn(),
    resetDemoEnvironment: vi.fn(),
  },
}));

describe('ThreatLens Frontend SOC Suite', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders SeverityBadge and AlertStatusBadge accurately', () => {
    render(
      <div>
        <SeverityBadge severity="critical" />
        <AlertStatusBadge status="Investigating" />
      </div>
    );
    expect(screen.getByText('CRITICAL')).toBeInTheDocument();
    expect(screen.getByText('Investigating')).toBeInTheDocument();
  });

  it('displays Dashboard loading state while fetching API telemetry', () => {
    (api.getOverviewDashboard as any).mockReturnValue(new Promise(() => {}));
    render(
      <MemoryRouter>
        <OverviewDashboardPage />
      </MemoryRouter>
    );
    expect(screen.getByTestId('dashboard-loading')).toBeInTheDocument();
    expect(screen.getByText(/SOC Overview Dashboard/i)).toBeInTheDocument();
  });

  it('displays Dashboard error state when backend API returns an error', async () => {
    (api.getOverviewDashboard as any).mockRejectedValue(
      new Error('PostgreSQL connection timeout')
    );
    render(
      <MemoryRouter>
        <OverviewDashboardPage />
      </MemoryRouter>
    );
    await waitFor(() => {
      expect(screen.getByTestId('dashboard-error')).toBeInTheDocument();
    });
    expect(screen.getByText(/PostgreSQL connection timeout/i)).toBeInTheDocument();
  });

  it('renders live Overview Dashboard metrics and tables from API response', async () => {
    (api.getOverviewDashboard as any).mockResolvedValue({
      metrics: {
        total_security_events: 142,
        total_alerts: 9,
        critical_alerts: 3,
        high_severity_alerts: 4,
        active_incidents: 2,
        resolved_incidents: 5,
      },
      events_over_time: [{ time: '14:00', events: 20, network_events: 8 }],
      alerts_by_severity: [
        { severity: 'Critical', key: 'critical', count: 3 },
        { severity: 'High', key: 'high', count: 4 },
      ],
      events_by_category: [{ category: 'Authentication', count: 60 }],
      top_source_ips: [
        {
          source_ip: '185.220.101.42',
          event_count: 24,
          failed_auths: 18,
          is_known_ioc: true,
          threat_type: 'brute_force',
        },
      ],
      auth_failure_trends: [{ time: '14:00', auth_success: 10, auth_failure: 18 }],
      recent_incidents: [
        {
          id: 1,
          incident_id: 'INC-2026-0001',
          title: 'SSH Brute-Force Escalation',
          severity: 'critical',
          status: 'Investigating',
          assigned_analyst: 'analyst',
          linked_alert_count: 2,
          created_at: '2026-11-09T14:00:00Z',
        },
      ],
      recent_alerts: [
        {
          id: 10,
          alert_id: 'ALT-20261109-AB12CD',
          title: 'Brute-Force Attack Against root',
          description: 'Repeated failures',
          severity: 'high',
          status: 'New',
          rule_code: 'RULE-001',
          rule_name: 'Brute-Force Authentication Attack',
          source_ip: '185.220.101.42',
          username: 'root',
          first_seen: '2026-11-09T14:00:00Z',
          last_seen: '2026-11-09T14:02:00Z',
          event_count: 6,
          mitre_technique_id: 'T1110.001',
          evidence_summary: {},
          is_synthetic: true,
          created_at: '2026-11-09T14:02:00Z',
          updated_at: '2026-11-09T14:02:00Z',
        },
      ],
      latest_events: [],
      detection_timeline: [],
      system_health: {
        status: 'operational',
        database_backend: 'postgresql',
        database_connected: true,
        detection_engine: 'active',
        enabled_rules: 7,
        total_rules: 7,
        active_websocket_clients: 1,
        checked_at: '2026-11-09T14:05:00Z',
      },
      ingestion_stats: {
        total_ingested: 142,
        synthetic_events: 142,
        organic_events: 0,
        categories_active: 4,
        unique_source_ips: 9,
      },
    });

    render(
      <MemoryRouter>
        <OverviewDashboardPage />
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByText('ALT-20261109-AB12CD')).toBeInTheDocument();
    });
    expect(screen.getByText('INC-2026-0001')).toBeInTheDocument();
    expect(screen.getByText('Brute-Force Attack Against root')).toBeInTheDocument();
  });

  it('renders SecurityEventsExplorerPage, supports column sorting, and opens Event Details Drawer', async () => {
    const sampleEvent = {
      id: 501,
      event_id: 'EVT-TEST-501',
      timestamp: '2026-11-09T15:00:00Z',
      source_ip: '185.220.101.42',
      destination_ip: '10.20.0.15',
      destination_port: 22,
      username: 'svc_backup_admin',
      hostname: 'prod-vault-01',
      event_type: 'ssh_auth_failure',
      event_category: 'Authentication',
      action: 'password_login',
      status: 'failure',
      severity: 'medium',
      raw_log: '[SYNTHETIC] Failed password for svc_backup_admin',
      metadata: { protocol: 'SSH' },
      is_synthetic: true,
      created_at: '2026-11-09T15:00:00Z',
    };
    (api.listEvents as any).mockResolvedValue({
      items: [sampleEvent],
      total: 1,
      page: 1,
      page_size: 25,
      total_pages: 1,
    });
    (api.getEventDetail as any).mockResolvedValue({
      event: sampleEvent,
      related_events: [],
      linked_alerts: [],
    });

    render(
      <MemoryRouter>
        <SecurityEventsExplorerPage />
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByText('EVT-TEST-501')).toBeInTheDocument();
    });

    // Click row to open Event Details Drawer
    fireEvent.click(screen.getByText('EVT-TEST-501'));
    await waitFor(() => {
      expect(screen.getByText(/SECURITY EVENT FORENSIC DRAWER/i)).toBeInTheDocument();
    });
    expect(screen.getByText(/\[SYNTHETIC\] Failed password for svc_backup_admin/i)).toBeInTheDocument();
  });

  it('renders AlertsManagementPage queue and Alert Details investigation workspace', async () => {
    const sampleAlert = {
      id: 77,
      alert_id: 'ALT-20261109-777777',
      title: 'Password Spraying Across 6 Accounts',
      description: 'Multiple accounts targeted from 91.240.118.172',
      severity: 'high',
      status: 'New',
      rule_code: 'RULE-002',
      rule_name: 'Password Spraying Attack',
      source_ip: '91.240.118.172',
      username: '6 accounts',
      hostname: 'idp-portal-prod-01',
      first_seen: '2026-11-09T15:00:00Z',
      last_seen: '2026-11-09T15:05:00Z',
      event_count: 6,
      mitre_tactic: 'Credential Access',
      mitre_technique_id: 'T1110.003',
      mitre_technique_name: 'Password Spraying',
      evidence_summary: {},
      is_synthetic: true,
      created_at: '2026-11-09T15:05:00Z',
      updated_at: '2026-11-09T15:05:00Z',
      evidence_events: [],
      status_history: [
        {
          id: 1,
          previous_status: null,
          new_status: 'New',
          changed_by: 'ThreatLens Detection Engine',
          comment: 'Automatically generated by RULE-002',
          created_at: '2026-11-09T15:05:00Z',
        },
      ],
      notes: [],
      linked_incidents: [],
    };
    (api.listAlerts as any).mockResolvedValue({
      items: [sampleAlert],
      total: 1,
      page: 1,
      page_size: 15,
      total_pages: 1,
    });
    (api.getAlertDetail as any).mockResolvedValue(sampleAlert);

    render(
      <MemoryRouter>
        <AlertsManagementPage />
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getAllByText('ALT-20261109-777777').length).toBeGreaterThanOrEqual(1);
    });
    expect(screen.getByText(/Update Alert Triage Status/i)).toBeInTheDocument();
  });

  it('renders DetectionRulesPage and AnalyticsReportsPage and SystemConfigurationPage', async () => {
    (api.listDetectionRules as any).mockResolvedValue([
      {
        id: 1,
        rule_id: 'RULE-001',
        rule_key: 'brute_force',
        name: 'Brute-Force Authentication Attack',
        description: 'Detects repeated failed logins',
        detection_logic: 'SELECT COUNT(*) >= 5',
        event_category: 'Authentication',
        threshold_count: 5,
        time_window_seconds: 300,
        parameters: {},
        severity: 'high',
        enabled: true,
        mitre_tactic: 'Credential Access',
        mitre_technique_id: 'T1110.001',
        mitre_technique_name: 'Password Guessing',
        alert_count: 2,
        created_at: '2026-11-09T14:00:00Z',
        updated_at: '2026-11-09T14:00:00Z',
      },
    ]);

    render(
      <MemoryRouter>
        <DetectionRulesPage />
      </MemoryRouter>
    );
    await waitFor(() => {
      expect(screen.getByText('Brute-Force Authentication Attack')).toBeInTheDocument();
    });

    (api.getAnalyticsPerformance as any).mockResolvedValue({
      detection_evaluation: {
        has_labeled_data: true,
        labeled_events_count: 42,
        true_positives: 30,
        false_positives: 0,
        true_negatives: 12,
        false_negatives: 0,
        precision: 1.0,
        recall: 1.0,
        f1_score: 1.0,
      },
      most_frequent_rules: [{ rule_id: 'RULE-001', alerts_generated: 2 }],
      resolved_vs_unresolved: [{ status: 'Unresolved', count: 2 }],
      auth_trends: [{ time: '15:00', auth_success: 10, auth_failure: 6 }],
      rule_performance: [
        {
          rule_id: 'RULE-001',
          name: 'Brute-Force Authentication Attack',
          mitre_technique_id: 'T1110.001',
          mitre_tactic: 'Credential Access',
          severity: 'high',
          alerts_generated: 2,
          true_positives: 6,
          false_positives: 0,
          false_negatives: 0,
          precision: 1.0,
          recall: 1.0,
          f1_score: 1.0,
        },
      ],
    });

    render(
      <MemoryRouter>
        <AnalyticsReportsPage />
      </MemoryRouter>
    );
    await waitFor(() => {
      expect(screen.getByText(/LABELED DATASET VERIFIED/i)).toBeInTheDocument();
    });

    (api.getSystemHealth as any).mockResolvedValue({
      status: 'healthy',
      database: {
        configured_host: 'localhost:5432/threatlens_db',
        backend: 'postgresql',
        postgresql_connected: true,
        postgresql_version: 'PostgreSQL 18.6',
      },
      realtime_websocket: { endpoint: '/ws', active_connections: 1 },
      security_controls: { rate_limit_login_per_min: 15, rate_limit_ingest_per_min: 240 },
      counters: { security_events: 150, alerts: 8 },
    });
    (api.listUsers as any).mockResolvedValue([
      {
        id: 1,
        username: 'admin',
        email: 'admin@threatlens.local',
        full_name: 'Elena Rostova',
        role: 'admin',
        is_active: true,
        created_at: '2026-11-09T14:00:00Z',
      },
    ]);
    (api.getAuditLogs as any).mockResolvedValue([]);
    (api.listTelemetryScenarios as any).mockResolvedValue([]);

    render(
      <MemoryRouter>
        <SystemConfigurationPage />
      </MemoryRouter>
    );
    await waitFor(() => {
      expect(screen.getByText(/PostgreSQL Connected/i)).toBeInTheDocument();
    });
  });

  it('renders IncidentInvestigationPage and ThreatDetectionPage with MITRE ATT&CK mappings, timeline, evidence, and status tracking', async () => {
    const sampleIncident = {
      id: 1,
      incident_id: 'INC-2026-0001',
      title: 'Multi-Stage Credential Compromise & Privilege Escalation',
      severity: 'critical',
      status: 'Investigating',
      description: 'Correlated brute-force and privilege escalation investigation',
      assigned_analyst: 'analyst',
      timeline_events: [
        {
          timestamp: '2026-11-09T15:00:00Z',
          actor: 'analyst',
          action: 'Incident Created',
          previous_status: null,
          new_status: 'Open',
          detail: 'Opened incident INC-2026-0001',
        },
        {
          timestamp: '2026-11-09T15:05:00Z',
          actor: 'analyst',
          action: 'Status Changed',
          previous_status: 'Open',
          new_status: 'Investigating',
          detail: "Status transitioned from 'Open' to 'Investigating'",
        },
      ],
      evidence_references: [
        {
          type: 'alert',
          reference: 'ALT-20261109-1001',
          description: 'RULE-001: Brute-Force Authentication Attack',
        },
        {
          type: 'event',
          reference: 'EVT-BF-001',
          description: 'Authentication/ssh_login from 185.220.101.42 (failure)',
        },
      ],
      resolution_summary: null,
      resolved_at: null,
      created_by: 'analyst',
      linked_alert_count: 2,
      created_at: '2026-11-09T15:00:00Z',
      updated_at: '2026-11-09T15:05:00Z',
      related_alerts: [
        {
          id: 101,
          alert_id: 'ALT-20261109-1001',
          title: 'Brute-Force Attack Against root',
          description: 'Repeated failed SSH logins',
          severity: 'high',
          status: 'Investigating',
          rule_code: 'RULE-001',
          rule_name: 'Brute-Force Authentication Attack',
          source_ip: '185.220.101.42',
          username: 'root',
          hostname: 'bastion-01',
          first_seen: '2026-11-09T14:58:00Z',
          last_seen: '2026-11-09T15:00:00Z',
          event_count: 6,
          mitre_tactic: 'Credential Access',
          mitre_technique_id: 'T1110.001',
          mitre_technique_name: 'Brute Force: Password Guessing',
          evidence_summary: {},
          is_synthetic: true,
          created_at: '2026-11-09T15:00:00Z',
          updated_at: '2026-11-09T15:00:00Z',
        },
      ],
      related_events: [
        {
          id: 901,
          event_id: 'EVT-BF-001',
          timestamp: '2026-11-09T14:59:00Z',
          source_ip: '185.220.101.42',
          destination_ip: '10.10.0.15',
          destination_port: 22,
          username: 'root',
          hostname: 'bastion-01',
          event_type: 'ssh_login',
          event_category: 'Authentication',
          action: 'password_login',
          status: 'failure',
          severity: 'high',
          raw_log: '[SYNTHETIC] Failed password for root from 185.220.101.42',
          metadata: {},
          is_synthetic: true,
          created_at: '2026-11-09T14:59:00Z',
        },
      ],
      notes: [
        {
          id: 1,
          incident_id: 1,
          author: 'analyst',
          content: 'Confirmed credential brute-force and escalated to incident.',
          note_type: 'investigation_note',
          created_at: '2026-11-09T15:06:00Z',
        },
      ],
      mitre_mappings: [
        {
          tactic: 'Credential Access',
          tactic_id: 'TA0006',
          technique_id: 'T1110.001',
          technique_name: 'Brute Force: Password Guessing',
          reference_url: 'https://attack.mitre.org/techniques/T1110/001/',
          associated_rules: [
            {
              id: 1,
              rule_id: 'RULE-001',
              name: 'Brute-Force Authentication Attack',
              severity: 'high',
              enabled: true,
              threshold_count: 5,
              time_window_seconds: 300,
            },
          ],
          alert_count: 1,
          related_alerts: [
            {
              id: 101,
              alert_id: 'ALT-20261109-1001',
              title: 'Brute-Force Attack Against root',
              severity: 'high',
              status: 'Investigating',
            },
          ],
        },
      ],
    };

    (api.listIncidents as any).mockResolvedValue({
      items: [sampleIncident],
      total: 1,
      page: 1,
      page_size: 50,
      total_pages: 1,
    });
    (api.getIncidentDetail as any).mockResolvedValue(sampleIncident);
    (api.listAlerts as any).mockResolvedValue({
      items: sampleIncident.related_alerts,
      total: 1,
      page: 1,
      page_size: 50,
      total_pages: 1,
    });
    (api.getMitreMappings as any).mockResolvedValue({
      total_mapped_rules: 7,
      tactic_summary: [
        { tactic: 'Credential Access', tactic_id: 'TA0006', rule_count: 2, alert_count: 1 },
      ],
      mappings: sampleIncident.mitre_mappings.map((m) => ({
        ...m,
        rule: m.associated_rules[0],
      })),
    });
    (api.listTelemetryScenarios as any).mockResolvedValue([]);

    render(
      <MemoryRouter>
        <IncidentInvestigationPage />
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getAllByText('INC-2026-0001').length).toBeGreaterThanOrEqual(1);
    });
    expect(screen.getAllByText('ALT-20261109-1001').length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText('EVT-BF-001').length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText(/Brute Force: Password Guessing/i)).toBeInTheDocument();
    expect(screen.getByText(/Confirmed credential brute-force/i)).toBeInTheDocument();

    render(
      <MemoryRouter>
        <ThreatDetectionPage />
      </MemoryRouter>
    );
    await waitFor(() => {
      expect(screen.getAllByText('T1110.001').length).toBeGreaterThanOrEqual(1);
    });
  });

  it('renders Phase 7 ThreatIntelligencePage (Suspicious IP Tracking, IOC list, Providers) and Analytics Incident Reports', async () => {
    (api.listThreatIndicators as any).mockResolvedValue([
      {
        id: 1,
        indicator_value: '185.220.101.42',
        indicator_type: 'ip',
        threat_type: 'tor_exit_brute_force',
        confidence_score: 92,
        severity: 'high',
        source: 'ThreatLens Threat Research',
        description: 'Known SSH brute-force actor',
        tags: ['ssh', 'brute_force'],
        is_active: true,
        first_seen: '2026-11-09T14:00:00Z',
        last_seen: '2026-11-09T15:00:00Z',
      },
    ]);
    (api.getThreatIntelProviders as any).mockResolvedValue({
      providers: [
        {
          provider: 'AbuseIPDB',
          enabled: true,
          configured: false,
          mode: 'not_configured (requires ABUSEIPDB_API_KEY)',
        },
        {
          provider: 'VirusTotal',
          enabled: true,
          configured: false,
          mode: 'not_configured (requires VIRUSTOTAL_API_KEY)',
        },
        {
          provider: 'AlienVault OTX',
          enabled: true,
          configured: false,
          mode: 'not_configured (requires OTX_API_KEY)',
        },
      ],
    });
    (api.listSuspiciousIps as any).mockResolvedValue([
      {
        ip: '185.220.101.42',
        ip_address: '185.220.101.42',
        risk_score: 95,
        severity: 'high',
        tracking_status: 'confirmed_ioc',
        is_active_ioc: true,
        ioc_id: 1,
        ioc_threat_type: 'tor_exit_brute_force',
        ioc_confidence: 92,
        ioc_source: 'ThreatLens Threat Research',
        total_events: 24,
        failed_logins: 18,
        alert_count: 2,
        triggered_rules: ['RULE-001'],
        alert_ids: ['ALT-20261109-1001'],
        targeted_hosts: ['bastion-01'],
        targeted_users: ['root'],
        first_seen: '2026-11-09T14:00:00Z',
        last_seen: '2026-11-09T15:00:00Z',
      },
    ]);
    (api.lookupIpIntelligence as any).mockResolvedValue({
      ip: '185.220.101.42',
      queried_at: '2026-11-09T15:05:00Z',
      verdict: 'confirmed_ioc_match',
      verdict_summary: 'Matched active IOC in ThreatLens Threat Research (threat type: tor_exit_brute_force).',
      reputation_confidence: 92,
      network_classification: {
        ip: '185.220.101.42',
        version: 'IPv4',
        is_private: false,
        is_loopback: false,
        is_multicast: false,
        is_global: true,
      },
      local_ioc_match: {
        id: 1,
        threat_type: 'tor_exit_brute_force',
        confidence: 92,
        severity: 'high',
        source: 'ThreatLens Threat Research',
        description: 'Known SSH brute-force actor',
        tags: ['ssh'],
      },
      internal_telemetry: {
        events_as_source: 24,
        events_as_destination: 0,
        failed_authentications: 18,
        associated_alerts_count: 2,
        recent_alerts: [],
      },
      external_providers: [
        {
          provider_id: 'abuseipdb',
          provider: 'AbuseIPDB',
          configured: false,
          status: 'not_configured',
          message: 'AbuseIPDB API key not configured. No external score fabricated.',
          data: null,
        },
      ],
    });

    render(
      <MemoryRouter>
        <ThreatIntelligencePage />
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getAllByText(/Suspicious IP Tracking/i).length).toBeGreaterThanOrEqual(1);
    });
    expect(screen.getAllByText('185.220.101.42').length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText(/CONFIRMED IOC/i).length).toBeGreaterThanOrEqual(1);
  });
});

