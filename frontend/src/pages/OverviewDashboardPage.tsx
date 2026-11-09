import React, { useCallback, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Activity,
  AlertOctagon,
  AlertTriangle,
  CheckCircle2,
  Database,
  Play,
  RefreshCw,
  Server,
  ShieldAlert,
  Terminal,
} from 'lucide-react';
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { api } from '../services/api';
import { OverviewDashboardData } from '../types';
import {
  AlertStatusBadge,
  IncidentStatusBadge,
  SeverityBadge,
} from '../components/SeverityBadge';
import { formatShortTime, formatTimestamp } from '../utils/formatters';

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#06b6d4',
};

export const OverviewDashboardPage: React.FC<{ refreshTrigger?: number }> = ({
  refreshTrigger,
}) => {
  const navigate = useNavigate();
  const [data, setData] = useState<OverviewDashboardData | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [simulating, setSimulating] = useState<boolean>(false);

  const fetchDashboard = useCallback(async () => {
    try {
      setError(null);
      const res = await api.getOverviewDashboard();
      setData(res);
    } catch (err: any) {
      setError(err.message || 'Failed to load SOC overview dashboard');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchDashboard();
  }, [fetchDashboard, refreshTrigger]);

  const handleQuickSimulate = async (scenarioId = 'all') => {
    setSimulating(true);
    try {
      await api.simulateScenario(scenarioId, 1);
      await fetchDashboard();
    } catch (err: any) {
      setError(err.message || 'Simulation failed');
    } finally {
      setSimulating(false);
    }
  };

  if (loading && !data) {
    return (
      <div className="space-y-6" data-testid="dashboard-loading">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-xl font-bold text-white">SOC Overview Dashboard</h1>
            <p className="text-xs text-slate-400">
              Loading real-time security telemetry and threat detection metrics...
            </p>
          </div>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-6 gap-4">
          {Array.from({ length: 6 }).map((_, i) => (
            <div key={i} className="soc-panel p-4 h-24 animate-pulse bg-[#0f1623]" />
          ))}
        </div>
      </div>
    );
  }

  if (error && !data) {
    return (
      <div className="soc-panel p-6 border-red-500/40 bg-red-950/10 text-red-300 space-y-3" data-testid="dashboard-error">
        <div className="flex items-center gap-2 font-semibold">
          <AlertOctagon className="w-5 h-5 text-red-400" />
          <span>Unable to Load Dashboard Telemetry</span>
        </div>
        <p className="text-xs text-red-200">{error}</p>
        <button
          onClick={fetchDashboard}
          className="px-3 py-1.5 rounded bg-red-600 hover:bg-red-500 text-white text-xs font-medium"
        >
          Retry Connection
        </button>
      </div>
    );
  }

  if (!data) return null;

  const { metrics, system_health, ingestion_stats } = data;

  return (
    <div className="space-y-6">
      {/* Page Header & Actions */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-white tracking-tight">
            Security Operations Center — Live Overview
          </h1>
          <p className="text-xs text-slate-400">
            Real-time SIEM event ingestion, MITRE ATT&CK rule correlation, and active incident posture
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={() => handleQuickSimulate('brute_force')}
            disabled={simulating}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-[#151f32] hover:bg-[#1e2c45] border border-cyan-500/30 text-cyan-300 text-xs font-medium"
          >
            <Play className="w-3.5 h-3.5" />
            Simulate Brute-Force
          </button>
          <button
            onClick={() => handleQuickSimulate('all')}
            disabled={simulating}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-medium"
          >
            <Play className="w-3.5 h-3.5" />
            {simulating ? 'Ingesting Telemetry...' : 'Run Full Attack Simulation'}
          </button>
          <button
            onClick={fetchDashboard}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-[#0f1623] hover:bg-[#151f32] border border-[#1e2c45] text-slate-200 text-xs"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Refresh
          </button>
        </div>
      </div>

      {/* 6 KPI Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-6 gap-4">
        <div
          onClick={() => navigate('/events')}
          className="soc-panel p-4 cursor-pointer hover:border-cyan-500/50 transition-colors"
        >
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Total Security Events</span>
            <Terminal className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="mt-2 text-2xl font-bold font-mono text-white">
            {metrics.total_security_events.toLocaleString()}
          </div>
          <div className="mt-1 text-[11px] text-slate-400">
            {ingestion_stats.synthetic_events} synthetic labeled
          </div>
        </div>

        <div
          onClick={() => navigate('/alerts')}
          className="soc-panel p-4 cursor-pointer hover:border-blue-500/50 transition-colors"
        >
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Total Alerts</span>
            <AlertTriangle className="w-4 h-4 text-blue-400" />
          </div>
          <div className="mt-2 text-2xl font-bold font-mono text-white">
            {metrics.total_alerts.toLocaleString()}
          </div>
          <div className="mt-1 text-[11px] text-blue-300">
            Across {system_health.enabled_rules} active rules
          </div>
        </div>

        <div
          onClick={() => navigate('/alerts?severity=critical')}
          className="soc-panel p-4 cursor-pointer border-l-2 border-l-red-500 hover:border-red-500/50 transition-colors"
        >
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Critical Alerts</span>
            <AlertOctagon className="w-4 h-4 text-red-400" />
          </div>
          <div className="mt-2 text-2xl font-bold font-mono text-red-400">
            {metrics.critical_alerts.toLocaleString()}
          </div>
          <div className="mt-1 text-[11px] text-red-300/80">Immediate triage required</div>
        </div>

        <div
          onClick={() => navigate('/alerts?severity=high')}
          className="soc-panel p-4 cursor-pointer border-l-2 border-l-orange-500 hover:border-orange-500/50 transition-colors"
        >
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>High-Severity Alerts</span>
            <ShieldAlert className="w-4 h-4 text-orange-400" />
          </div>
          <div className="mt-2 text-2xl font-bold font-mono text-orange-400">
            {metrics.high_severity_alerts.toLocaleString()}
          </div>
          <div className="mt-1 text-[11px] text-orange-300/80">High priority detections</div>
        </div>

        <div
          onClick={() => navigate('/incidents')}
          className="soc-panel p-4 cursor-pointer hover:border-yellow-500/50 transition-colors"
        >
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Active Incidents</span>
            <Activity className="w-4 h-4 text-yellow-400" />
          </div>
          <div className="mt-2 text-2xl font-bold font-mono text-yellow-300">
            {metrics.active_incidents.toLocaleString()}
          </div>
          <div className="mt-1 text-[11px] text-slate-400">Open / Investigating</div>
        </div>

        <div
          onClick={() => navigate('/incidents?status=Resolved')}
          className="soc-panel p-4 cursor-pointer border-l-2 border-l-emerald-500 hover:border-emerald-500/50 transition-colors"
        >
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Resolved Incidents</span>
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="mt-2 text-2xl font-bold font-mono text-emerald-400">
            {metrics.resolved_incidents.toLocaleString()}
          </div>
          <div className="mt-1 text-[11px] text-emerald-300/80">Contained & closed</div>
        </div>
      </div>

      {/* Row 1 Visualizations: Security Events Over Time & Alerts by Severity */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="soc-panel p-4 lg:col-span-2">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-sm font-semibold text-white">Security Events Over Time</h2>
              <p className="text-[11px] text-slate-400">
                Chronological event volume and network activity across ingestion windows
              </p>
            </div>
            <span className="text-[11px] font-mono text-cyan-400">LIVE STREAM</span>
          </div>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={data.events_over_time}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e2c45" />
                <XAxis dataKey="time" stroke="#94a3b8" fontSize={11} />
                <YAxis stroke="#94a3b8" fontSize={11} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0f1623',
                    borderColor: '#243554',
                    fontSize: '12px',
                    color: '#f1f5f9',
                  }}
                />
                <Legend wrapperStyle={{ fontSize: '11px' }} />
                <Area
                  type="monotone"
                  dataKey="events"
                  name="Total Events"
                  stroke="#06b6d4"
                  fill="#06b6d4"
                  fillOpacity={0.18}
                />
                <Area
                  type="monotone"
                  dataKey="network_events"
                  name="Network Events"
                  stroke="#3b82f6"
                  fill="#3b82f6"
                  fillOpacity={0.12}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="soc-panel p-4">
          <div className="mb-4">
            <h2 className="text-sm font-semibold text-white">Alerts Grouped by Severity</h2>
            <p className="text-[11px] text-slate-400">
              Distribution across Critical, High, Medium, and Low severity rules
            </p>
          </div>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={data.alerts_by_severity} layout="vertical">
                <CartesianGrid strokeDasharray="3 3" stroke="#1e2c45" />
                <XAxis type="number" stroke="#94a3b8" fontSize={11} allowDecimals={false} />
                <YAxis dataKey="severity" type="category" stroke="#94a3b8" fontSize={11} width={70} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0f1623',
                    borderColor: '#243554',
                    fontSize: '12px',
                  }}
                />
                <Bar dataKey="count" name="Alerts" radius={[0, 4, 4, 0]}>
                  {data.alerts_by_severity.map((entry) => (
                    <Cell
                      key={entry.key}
                      fill={SEVERITY_COLORS[entry.key] || '#06b6d4'}
                    />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Row 2 Visualizations: Event Distribution by Category, Auth Failure Trends, Top Source IPs */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Event Distribution by Category */}
        <div className="soc-panel p-4">
          <div className="mb-4">
            <h2 className="text-sm font-semibold text-white">Event Distribution by Category</h2>
            <p className="text-[11px] text-slate-400">
              Normalized telemetry volume by security domain
            </p>
          </div>
          <div className="h-60">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={data.events_by_category}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e2c45" />
                <XAxis dataKey="category" stroke="#94a3b8" fontSize={10} />
                <YAxis stroke="#94a3b8" fontSize={11} allowDecimals={false} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0f1623',
                    borderColor: '#243554',
                    fontSize: '12px',
                  }}
                />
                <Bar dataKey="count" name="Events" fill="#3b82f6" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Authentication Failure Trends */}
        <div className="soc-panel p-4">
          <div className="mb-4">
            <h2 className="text-sm font-semibold text-white">Authentication Failure Trends</h2>
            <p className="text-[11px] text-slate-400">
              Successful vs. failed login telemetry correlation
            </p>
          </div>
          <div className="h-60">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={data.auth_failure_trends}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e2c45" />
                <XAxis dataKey="time" stroke="#94a3b8" fontSize={11} />
                <YAxis stroke="#94a3b8" fontSize={11} allowDecimals={false} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0f1623',
                    borderColor: '#243554',
                    fontSize: '12px',
                  }}
                />
                <Legend wrapperStyle={{ fontSize: '11px' }} />
                <Bar dataKey="auth_failure" name="Auth Failures" fill="#f97316" radius={[3, 3, 0, 0]} />
                <Bar dataKey="auth_success" name="Auth Success" fill="#10b981" radius={[3, 3, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Top Source IP Addresses */}
        <div className="soc-panel p-4 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-3">
              <div>
                <h2 className="text-sm font-semibold text-white">Top Source IP Addresses</h2>
                <p className="text-[11px] text-slate-400">
                  Highest-volume telemetry sources & IOC correlation
                </p>
              </div>
              <button
                onClick={() => navigate('/threat-intelligence')}
                className="text-[11px] text-cyan-400 hover:underline"
              >
                IOC Lookup →
              </button>
            </div>
            <div className="space-y-2 max-h-56 overflow-y-auto">
              {data.top_source_ips.map((item) => (
                <div
                  key={item.source_ip}
                  onClick={() =>
                    navigate(`/threat-intelligence?ip=${encodeURIComponent(item.source_ip)}`)
                  }
                  className="p-2 rounded bg-[#151f32] border border-[#1e2c45] hover:border-cyan-500/40 cursor-pointer flex items-center justify-between text-xs"
                >
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-mono font-medium text-slate-100">
                        {item.source_ip}
                      </span>
                      {item.is_known_ioc && (
                        <span className="px-1.5 py-0.5 rounded bg-red-500/15 text-red-400 border border-red-500/30 text-[10px] font-mono uppercase">
                          IOC: {item.threat_type}
                        </span>
                      )}
                    </div>
                    <div className="text-[11px] text-slate-400">
                      Auth failures: <span className="text-orange-300">{item.failed_auths}</span>
                    </div>
                  </div>
                  <div className="text-right font-mono">
                    <div className="text-cyan-300 font-semibold">{item.event_count}</div>
                    <div className="text-[10px] text-slate-400">events</div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Row 3: Recent Alerts Table & Detection Activity Timeline */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Recent Alerts Table */}
        <div className="soc-panel p-4 lg:col-span-2">
          <div className="flex items-center justify-between mb-3">
            <div>
              <h2 className="text-sm font-semibold text-white">Recent Detection Alerts</h2>
              <p className="text-[11px] text-slate-400">
                Real-time rule detections persisted in PostgreSQL
              </p>
            </div>
            <button
              onClick={() => navigate('/alerts')}
              className="text-xs text-cyan-400 hover:underline"
            >
              View All Alerts →
            </button>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-[#1e2c45] text-slate-400 text-[11px] uppercase">
                  <th className="py-2 px-2">Alert ID</th>
                  <th className="py-2 px-2">Severity</th>
                  <th className="py-2 px-2">Title & MITRE</th>
                  <th className="py-2 px-2">Source IP</th>
                  <th className="py-2 px-2">Events</th>
                  <th className="py-2 px-2">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1e2c45]">
                {data.recent_alerts.map((al) => (
                  <tr
                    key={al.id}
                    onClick={() => navigate(`/alerts?alertId=${al.id}`)}
                    className="hover:bg-[#151f32] cursor-pointer transition-colors"
                  >
                    <td className="py-2.5 px-2 font-mono text-cyan-400 whitespace-nowrap">
                      {al.alert_id}
                    </td>
                    <td className="py-2.5 px-2">
                      <SeverityBadge severity={al.severity} />
                    </td>
                    <td className="py-2.5 px-2">
                      <div className="font-medium text-slate-100">{al.title}</div>
                      <div className="text-[11px] text-slate-400 font-mono">
                        {al.rule_code} • {al.mitre_technique_id || 'SIEM'}
                      </div>
                    </td>
                    <td className="py-2.5 px-2 font-mono text-slate-300">
                      {al.source_ip || '—'}
                    </td>
                    <td className="py-2.5 px-2 font-mono text-slate-300">{al.event_count}</td>
                    <td className="py-2.5 px-2">
                      <AlertStatusBadge status={al.status} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Detection Activity Timeline & Recent Incidents */}
        <div className="space-y-6">
          <div className="soc-panel p-4">
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-sm font-semibold text-white">Detection Activity Timeline</h2>
              <span className="text-[10px] font-mono text-slate-400">CHRONOLOGICAL</span>
            </div>
            <div className="space-y-3 max-h-60 overflow-y-auto pr-1">
              {data.detection_timeline.map((item) => (
                <div
                  key={item.id}
                  className="relative pl-4 border-l-2 border-cyan-500/40 text-xs space-y-0.5"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-[11px] text-cyan-400">
                      {item.rule_code} ({item.mitre_technique_id})
                    </span>
                    <span className="font-mono text-[10px] text-slate-400">
                      {formatShortTime(item.timestamp)}
                    </span>
                  </div>
                  <div className="text-slate-200 font-medium">{item.title}</div>
                  <div className="text-[11px] text-slate-400">
                    Source: <span className="font-mono text-slate-300">{item.source_ip}</span> •{' '}
                    {item.event_count} correlated event(s)
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Recent Security Incidents */}
          <div className="soc-panel p-4">
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-sm font-semibold text-white">Recent Security Incidents</h2>
              <button
                onClick={() => navigate('/incidents')}
                className="text-xs text-cyan-400 hover:underline"
              >
                Workspace →
              </button>
            </div>
            <div className="space-y-2">
              {data.recent_incidents.map((inc) => (
                <div
                  key={inc.id}
                  onClick={() => navigate(`/incidents?incidentId=${inc.id}`)}
                  className="p-2.5 rounded bg-[#151f32] border border-[#1e2c45] hover:border-cyan-500/40 cursor-pointer text-xs space-y-1"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-orange-400 font-semibold">
                      {inc.incident_id}
                    </span>
                    <IncidentStatusBadge status={inc.status} />
                  </div>
                  <div className="font-medium text-slate-100">{inc.title}</div>
                  <div className="flex items-center justify-between text-[11px] text-slate-400">
                    <span>Assignee: {inc.assigned_analyst || 'Unassigned'}</span>
                    <span>{inc.linked_alert_count} linked alert(s)</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Row 4: Latest Security Events & System Health / Ingestion Statistics */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Latest Security Events */}
        <div className="soc-panel p-4 lg:col-span-2">
          <div className="flex items-center justify-between mb-3">
            <div>
              <h2 className="text-sm font-semibold text-white">Latest Security Events</h2>
              <p className="text-[11px] text-slate-400">
                Normalized telemetry stream across Authentication, Network, Authorization, and Endpoint sources
              </p>
            </div>
            <button
              onClick={() => navigate('/events')}
              className="text-xs text-cyan-400 hover:underline"
            >
              Open Event Explorer →
            </button>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-[#1e2c45] text-slate-400 text-[11px] uppercase">
                  <th className="py-2 px-2">Timestamp</th>
                  <th className="py-2 px-2">Category</th>
                  <th className="py-2 px-2">Event Type</th>
                  <th className="py-2 px-2">Source IP</th>
                  <th className="py-2 px-2">User / Host</th>
                  <th className="py-2 px-2">Severity</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1e2c45]">
                {data.latest_events.slice(0, 8).map((ev) => (
                  <tr
                    key={ev.id}
                    onClick={() =>
                      navigate(`/events?search=${encodeURIComponent(ev.event_id)}`)
                    }
                    className="hover:bg-[#151f32] cursor-pointer"
                  >
                    <td className="py-2 px-2 font-mono text-[11px] text-slate-300 whitespace-nowrap">
                      {formatTimestamp(ev.timestamp)}
                    </td>
                    <td className="py-2 px-2 text-cyan-300">{ev.event_category}</td>
                    <td className="py-2 px-2 font-mono text-slate-200">{ev.event_type}</td>
                    <td className="py-2 px-2 font-mono text-slate-300">{ev.source_ip}</td>
                    <td className="py-2 px-2 text-slate-300">
                      {ev.username || '—'} @ {ev.hostname || '—'}
                    </td>
                    <td className="py-2 px-2">
                      <SeverityBadge severity={ev.severity} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* System Health & Event Ingestion Statistics */}
        <div className="soc-panel p-4 space-y-4">
          <div>
            <h2 className="text-sm font-semibold text-white">
              System Health & Ingestion Statistics
            </h2>
            <p className="text-[11px] text-slate-400">
              Platform pipeline diagnostics and database telemetry counters
            </p>
          </div>

          <div className="space-y-2 text-xs">
            <div className="p-2.5 rounded bg-[#151f32] border border-[#1e2c45] flex items-center justify-between">
              <span className="text-slate-300 flex items-center gap-2">
                <Server className="w-4 h-4 text-emerald-400" />
                Ingestion Engine Status
              </span>
              <span className="px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-300 border border-emerald-500/30 font-mono text-[11px] uppercase">
                {system_health.status}
              </span>
            </div>

            <div className="p-2.5 rounded bg-[#151f32] border border-[#1e2c45] flex items-center justify-between">
              <span className="text-slate-300 flex items-center gap-2">
                <Database className="w-4 h-4 text-cyan-400" />
                Database Engine
              </span>
              <span className="font-mono text-slate-200 text-[11px]">
                {system_health.database_backend}
              </span>
            </div>

            <div className="grid grid-cols-2 gap-2 pt-1">
              <div className="p-2.5 rounded bg-[#151f32] border border-[#1e2c45]">
                <div className="text-[11px] text-slate-400">Total Ingested</div>
                <div className="text-base font-bold font-mono text-white">
                  {ingestion_stats.total_ingested}
                </div>
              </div>
              <div className="p-2.5 rounded bg-[#151f32] border border-[#1e2c45]">
                <div className="text-[11px] text-slate-400">Synthetic Labeled</div>
                <div className="text-base font-bold font-mono text-cyan-300">
                  {ingestion_stats.synthetic_events}
                </div>
              </div>
              <div className="p-2.5 rounded bg-[#151f32] border border-[#1e2c45]">
                <div className="text-[11px] text-slate-400">Unique Source IPs</div>
                <div className="text-base font-bold font-mono text-white">
                  {ingestion_stats.unique_source_ips}
                </div>
              </div>
              <div className="p-2.5 rounded bg-[#151f32] border border-[#1e2c45]">
                <div className="text-[11px] text-slate-400">Active Rules</div>
                <div className="text-base font-bold font-mono text-emerald-400">
                  {system_health.enabled_rules} / {system_health.total_rules}
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

