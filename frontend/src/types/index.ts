export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type AlertStatus =
  | 'New'
  | 'Acknowledged'
  | 'Investigating'
  | 'Resolved'
  | 'False Positive';

export type IncidentStatus =
  | 'Open'
  | 'Investigating'
  | 'Contained'
  | 'Resolved'
  | 'Closed';

export interface UserProfile {
  id: number;
  username: string;
  email: string;
  full_name: string;
  role: string;
  is_active: boolean;
  last_login?: string | null;
  created_at: string;
}

export interface SecurityEvent {
  id: number;
  event_id: string;
  timestamp: string;
  source_ip: string;
  destination_ip?: string | null;
  destination_port?: number | null;
  username?: string | null;
  hostname?: string | null;
  event_type: string;
  event_category: string;
  action: string;
  status: string;
  severity: SeverityLevel;
  raw_log: string;
  metadata: Record<string, any>;
  is_synthetic: boolean;
  created_at: string;
}

export interface DetectionRule {
  id: number;
  rule_id: string;
  rule_key: string;
  name: string;
  description: string;
  detection_logic: string;
  event_category: string;
  threshold_count: number;
  time_window_seconds: number;
  parameters: Record<string, any>;
  severity: SeverityLevel;
  enabled: boolean;
  mitre_tactic?: string | null;
  mitre_technique_id?: string | null;
  mitre_technique_name?: string | null;
  alert_count: number;
  created_at: string;
  updated_at: string;
}

export interface InvestigationNote {
  id: number;
  alert_id?: number | null;
  incident_id?: number | null;
  author: string;
  content: string;
  note_type: string;
  created_at: string;
}

export interface AlertStatusHistoryItem {
  id: number;
  alert_id: number;
  previous_status?: string | null;
  new_status: string;
  changed_by: string;
  comment?: string | null;
  created_at: string;
}

export interface AlertItem {
  id: number;
  alert_id: string;
  title: string;
  description: string;
  severity: SeverityLevel;
  status: AlertStatus;
  rule_id_fk?: number | null;
  rule_code: string;
  rule_name: string;
  source_ip?: string | null;
  username?: string | null;
  hostname?: string | null;
  first_seen: string;
  last_seen: string;
  event_count: number;
  mitre_tactic?: string | null;
  mitre_technique_id?: string | null;
  mitre_technique_name?: string | null;
  evidence_summary: Record<string, any>;
  assigned_to?: string | null;
  is_synthetic: boolean;
  created_at: string;
  updated_at: string;
}

export interface AlertDetail extends AlertItem {
  evidence_events: SecurityEvent[];
  notes: InvestigationNote[];
  status_history: AlertStatusHistoryItem[];
  linked_incident_ids: string[];
}

export interface IncidentTimelineItem {
  timestamp: string;
  actor: string;
  action: string;
  detail: string;
  previous_status?: string | null;
  new_status?: string | null;
  comment?: string | null;
  previous_analyst?: string | null;
  new_analyst?: string | null;
  note_type?: string | null;
}

export interface IncidentEvidenceRef {
  type: string;
  reference: string;
  description: string;
  alert_id?: number;
  event_id?: number;
  rule_code?: string;
  source_ip?: string;
  event_category?: string;
  added_by?: string;
  added_at?: string;
}

export interface IncidentStatusHistoryItem {
  previous_status?: string | null;
  new_status: string;
  changed_by: string;
  comment?: string | null;
  timestamp: string;
}

export interface MitreMappingItem {
  tactic: string;
  mitre_tactic?: string;
  tactic_id?: string;
  technique_id: string;
  mitre_technique_id?: string;
  technique_name: string;
  mitre_technique_name?: string;
  reference_url: string;
  rule?: {
    id: number;
    rule_id: string;
    rule_key?: string;
    name: string;
    severity: SeverityLevel;
    enabled: boolean;
    threshold_count?: number;
    time_window_seconds?: number;
  };
  associated_rules?: Array<{
    id: number;
    rule_id: string;
    rule_key?: string;
    name: string;
    severity: SeverityLevel;
    enabled: boolean;
    threshold_count?: number;
    time_window_seconds?: number;
  }>;
  alert_count: number;
  related_alerts: Array<{
    id: number;
    alert_id: string;
    title: string;
    severity: SeverityLevel;
    status: AlertStatus;
    rule_code?: string;
    source_ip?: string | null;
    username?: string | null;
    last_seen?: string | null;
  }>;
}

export interface IncidentItem {
  id: number;
  incident_id: string;
  title: string;
  severity: SeverityLevel;
  status: IncidentStatus;
  description: string;
  assigned_analyst?: string | null;
  timeline_events: IncidentTimelineItem[];
  evidence_references: IncidentEvidenceRef[];
  resolution_summary?: string | null;
  resolved_at?: string | null;
  created_by?: string | null;
  linked_alert_count: number;
  created_at: string;
  updated_at: string;
}

export interface IncidentDetail extends IncidentItem {
  related_alerts: AlertItem[];
  related_events: SecurityEvent[];
  notes: InvestigationNote[];
  status_history?: IncidentStatusHistoryItem[];
  mitre_mappings?: MitreMappingItem[];
}

export interface ThreatIndicator {
  id: number;
  indicator_type: string;
  indicator_value: string;
  threat_type: string;
  severity: SeverityLevel;
  confidence: number;
  source: string;
  description?: string | null;
  tags: string[];
  is_active: boolean;
  first_seen: string;
  last_seen: string;
  hit_count: number;
  created_at: string;
  updated_at: string;
}

export interface OverviewDashboardData {
  metrics: {
    total_security_events: number;
    total_alerts: number;
    critical_alerts: number;
    high_severity_alerts: number;
    active_incidents: number;
    resolved_incidents: number;
  };
  events_over_time: Array<{
    time: string;
    events: number;
    auth_success: number;
    auth_failure: number;
    network_events: number;
  }>;
  alerts_by_severity: Array<{
    severity: string;
    key: string;
    count: number;
  }>;
  events_by_category: Array<{
    category: string;
    count: number;
  }>;
  top_source_ips: Array<{
    source_ip: string;
    event_count: number;
    failed_auths: number;
    is_known_ioc: boolean;
    threat_type?: string | null;
  }>;
  auth_failure_trends: Array<{
    time: string;
    auth_success: number;
    auth_failure: number;
  }>;
  recent_incidents: Array<{
    id: number;
    incident_id: string;
    title: string;
    severity: SeverityLevel;
    status: IncidentStatus;
    assigned_analyst?: string | null;
    linked_alert_count: number;
    created_at: string;
  }>;
  recent_alerts: AlertItem[];
  latest_events: SecurityEvent[];
  detection_timeline: Array<{
    id: string;
    timestamp: string;
    rule_code: string;
    rule_name: string;
    title: string;
    severity: SeverityLevel;
    source_ip?: string | null;
    mitre_technique_id?: string | null;
    event_count: number;
  }>;
  system_health: {
    status: string;
    database_backend: string;
    database_connected: boolean;
    detection_engine: string;
    enabled_rules: number;
    total_rules: number;
    active_websocket_clients: number;
    checked_at: string;
  };
  ingestion_stats: {
    total_ingested: number;
    synthetic_events: number;
    organic_events: number;
    categories_active: number;
    unique_source_ips: number;
  };
}

export interface TelemetryScenario {
  id: string;
  name: string;
  category: string;
  is_attack: boolean;
  expected_rule_id?: string | null;
  mitre_technique_id?: string | null;
  description: string;
}

