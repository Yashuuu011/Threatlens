import React, { useCallback, useEffect, useState } from 'react';
import {
  Database,
  Play,
  RefreshCw,
  RotateCcw,
  Shield,
  Terminal,
  Users,
} from 'lucide-react';
import { api } from '../services/api';
import { TelemetryScenario, UserProfile } from '../types';
import { formatTimestamp } from '../utils/formatters';

export const SystemConfigurationPage: React.FC = () => {
  const [health, setHealth] = useState<any | null>(null);
  const [users, setUsers] = useState<UserProfile[]>([]);
  const [auditLogs, setAuditLogs] = useState<any[]>([]);
  const [scenarios, setScenarios] = useState<TelemetryScenario[]>([]);
  const [loading, setLoading] = useState(true);

  const [selectedScenario, setSelectedScenario] = useState('all');
  const [volumeMultiplier, setVolumeMultiplier] = useState(1);
  const [simBusy, setSimBusy] = useState(false);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);
  const [auditSearch, setAuditSearch] = useState('');
  const [auditStatusFilter, setAuditStatusFilter] = useState('all');

  const loadSystemData = useCallback(async () => {
    setLoading(true);
    try {
      const [h, u, logs, scens] = await Promise.all([
        api.getSystemHealth(),
        api.listUsers(),
        api.getAuditLogs({
          limit: 60,
          search: auditSearch.trim() || undefined,
          status: auditStatusFilter !== 'all' ? auditStatusFilter : undefined,
        }),
        api.listTelemetryScenarios(),
      ]);
      setHealth(h);
      setUsers(u);
      setAuditLogs(logs);
      setScenarios(scens);
    } finally {
      setLoading(false);
    }
  }, [auditSearch, auditStatusFilter]);

  useEffect(() => {
    loadSystemData();
  }, [loadSystemData]);

  const handleSimulate = async (e: React.FormEvent) => {
    e.preventDefault();
    setSimBusy(true);
    setStatusMessage(null);
    try {
      const res = await api.simulateScenario(selectedScenario, volumeMultiplier);
      setStatusMessage(
        `Executed synthetic scenario '${res.scenario_id}' (volume ${volumeMultiplier}x): Ingested ${res.accepted_count} events and triggered ${res.generated_alerts_count} alert(s).`
      );
      await loadSystemData();
    } catch (err: any) {
      setStatusMessage(`Error: ${err.message}`);
    } finally {
      setSimBusy(false);
    }
  };

  const handleResetDemo = async () => {
    setSimBusy(true);
    setStatusMessage(null);
    try {
      await api.resetDemoEnvironment();
      setStatusMessage(
        'Database reset and re-seeded with baseline synthetic telemetry, rules, IOCs, and active incident.'
      );
      await loadSystemData();
    } finally {
      setSimBusy(false);
    }
  };

  if (loading || !health) {
    return (
      <div className="soc-panel p-12 text-center text-xs text-slate-400">
        Loading system configuration, RBAC directory, and audit logs...
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-white">
            System Configuration, Telemetry Generator & Audit Trail
          </h1>
          <p className="text-xs text-slate-400">
            Platform diagnostics, RBAC operator accounts, synthetic telemetry controller, and security audit logging
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={handleResetDemo}
            disabled={simBusy}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-[#151f32] hover:bg-red-950/40 border border-red-500/40 text-red-300 text-xs font-medium"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            Reset & Re-Seed Baseline Dataset
          </button>
          <button
            onClick={loadSystemData}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-[#0f1623] hover:bg-[#151f32] border border-[#1e2c45] text-slate-200 text-xs"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Refresh
          </button>
        </div>
      </div>

      {statusMessage && (
        <div className="p-3 rounded bg-cyan-500/15 border border-cyan-500/40 text-cyan-200 text-xs">
          {statusMessage}
        </div>
      )}

      {/* Row 1: Platform Architecture Diagnostics & Synthetic Telemetry Generator */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Diagnostics */}
        <div className="soc-panel p-5 space-y-4 text-xs">
          <div className="flex items-center gap-2 font-semibold text-white text-sm">
            <Database className="w-4 h-4 text-cyan-400" />
            <span>Infrastructure & Security Controls Posture</span>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div className="p-3 rounded bg-[#151f32] border border-[#243554]">
              <div className="text-[10px] uppercase text-slate-400">
                PostgreSQL ({health.database.configured_host || 'localhost:5432'})
              </div>
              <div className="font-mono font-semibold text-white mt-0.5">
                Active Engine: {health.database.backend}
              </div>
              {health.database.postgresql_connected ? (
                <div className="text-[11px] text-emerald-400 mt-0.5">
                  PostgreSQL Connected ({health.database.postgresql_version || 'live'})
                </div>
              ) : (
                <div className="text-[11px] text-yellow-300 mt-0.5">
                  PostgreSQL Unreachable ({health.database.postgresql_error || 'not running'}) — Using SQLite Fallback
                </div>
              )}
            </div>
            <div className="p-3 rounded bg-[#151f32] border border-[#243554]">
              <div className="text-[10px] uppercase text-slate-400">WebSocket Stream</div>
              <div className="font-mono font-semibold text-white mt-0.5">
                {health.realtime_websocket.endpoint} ({health.realtime_websocket.active_connections} clients)
              </div>
              <div className="text-[11px] text-cyan-300 mt-0.5">Polling fallback enabled</div>
            </div>
            <div className="p-3 rounded bg-[#151f32] border border-[#243554]">
              <div className="text-[10px] uppercase text-slate-400">Auth & RBAC</div>
              <div className="font-mono font-semibold text-emerald-400 mt-0.5">
                JWT HS256 + bcrypt
              </div>
              <div className="text-[11px] text-slate-400 mt-0.5">
                Login Rate Limit: {health.security_controls.rate_limit_login_per_min}/min
              </div>
            </div>
            <div className="p-3 rounded bg-[#151f32] border border-[#243554]">
              <div className="text-[10px] uppercase text-slate-400">Ingestion Pipeline</div>
              <div className="font-mono font-semibold text-white mt-0.5">
                {health.counters.security_events} Events / {health.counters.alerts} Alerts
              </div>
              <div className="text-[11px] text-slate-400 mt-0.5">
                Ingest Rate Limit: {health.security_controls.rate_limit_ingest_per_min}/min
              </div>
            </div>
          </div>
        </div>

        {/* Synthetic Telemetry Controller */}
        <div className="soc-panel p-5 space-y-4 text-xs">
          <div className="flex items-center gap-2 font-semibold text-white text-sm">
            <Terminal className="w-4 h-4 text-cyan-400" />
            <span>Synthetic Security Telemetry Generator</span>
          </div>
          <p className="text-slate-400">
            Generate configurable volumes of clearly labeled synthetic security telemetry (`is_synthetic: true`) to stress-test event ingestion and rule correlation.
          </p>

          <form onSubmit={handleSimulate} className="space-y-3">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label className="block text-slate-300 mb-1">Telemetry Scenario</label>
                <select
                  value={selectedScenario}
                  onChange={(e) => setSelectedScenario(e.target.value)}
                  className="w-full bg-[#090d16] border border-[#1e2c45] rounded px-3 py-2 text-white"
                >
                  <option value="all">All 11 Scenarios (Full Balanced Suite)</option>
                  <option value="normal_mode">NORMAL MODE (Benign Logins, Typos, Network & System)</option>
                  <option value="attack_mode">ATTACK SIMULATION MODE (Core Attack Suite)</option>
                  {scenarios.map((s) => (
                    <option key={s.id} value={s.id}>
                      {s.name} ({s.is_attack ? s.expected_rule_id : 'Benign'})
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className="block text-slate-300 mb-1">
                  Event Volume Multiplier ({volumeMultiplier}x)
                </label>
                <input
                  type="range"
                  min={1}
                  max={5}
                  value={volumeMultiplier}
                  onChange={(e) => setVolumeMultiplier(Number(e.target.value))}
                  className="w-full mt-2 accent-cyan-500"
                />
              </div>
            </div>

            <div className="flex justify-end">
              <button
                type="submit"
                disabled={simBusy}
                className="inline-flex items-center gap-1.5 px-4 py-2 rounded bg-cyan-600 hover:bg-cyan-500 text-white font-medium"
              >
                <Play className="w-3.5 h-3.5" />
                {simBusy ? 'Generating & Ingesting...' : 'Generate Synthetic Telemetry'}
              </button>
            </div>
          </form>
        </div>
      </div>

      {/* Row 2: RBAC Users & Audit Logs */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* RBAC Users */}
        <div className="soc-panel p-4 space-y-3 text-xs">
          <div className="flex items-center gap-2 font-semibold text-white text-sm">
            <Users className="w-4 h-4 text-cyan-400" />
            <span>SOC Operator Accounts (RBAC)</span>
          </div>
          <div className="space-y-2">
            {users.map((u) => (
              <div
                key={u.id}
                className="p-3 rounded bg-[#151f32] border border-[#1e2c45] flex items-center justify-between"
              >
                <div>
                  <div className="font-semibold text-white">{u.full_name}</div>
                  <div className="font-mono text-[11px] text-slate-400">
                    {u.username} • {u.email}
                  </div>
                </div>
                <span className="px-2 py-0.5 rounded bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 font-mono text-[10px] uppercase">
                  {u.role}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Security Audit Log Table */}
        <div className="soc-panel p-4 lg:col-span-2 space-y-3 text-xs">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <div className="flex items-center gap-2 font-semibold text-white text-sm">
              <Shield className="w-4 h-4 text-emerald-400" />
              <span>Immutable Security Audit Log ({auditLogs.length})</span>
            </div>
            <div className="flex items-center gap-2">
              <input
                type="text"
                value={auditSearch}
                onChange={(e) => setAuditSearch(e.target.value)}
                placeholder="Search actor, action, resource..."
                className="bg-[#090d16] border border-[#1e2c45] rounded px-2.5 py-1 text-white text-xs"
              />
              <select
                value={auditStatusFilter}
                onChange={(e) => setAuditStatusFilter(e.target.value)}
                className="bg-[#090d16] border border-[#1e2c45] rounded px-2 py-1 text-white text-xs"
              >
                <option value="all">All Statuses</option>
                <option value="success">Success</option>
                <option value="failure">Failure</option>
              </select>
            </div>
          </div>

          <div className="overflow-x-auto max-h-72 overflow-y-auto border border-[#1e2c45] rounded">
            <table className="w-full text-left border-collapse text-[11px]">
              <thead>
                <tr className="bg-[#0c121e] border-b border-[#1e2c45] text-slate-400 uppercase">
                  <th className="py-2 px-2.5">Timestamp</th>
                  <th className="py-2 px-2.5">Actor</th>
                  <th className="py-2 px-2.5">Action</th>
                  <th className="py-2 px-2.5">Resource</th>
                  <th className="py-2 px-2.5">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1e2c45]">
                {auditLogs.map((log) => (
                  <tr key={log.id} className="hover:bg-[#151f32]">
                    <td className="py-2 px-2.5 font-mono text-slate-300 whitespace-nowrap">
                      {formatTimestamp(log.created_at)}
                    </td>
                    <td className="py-2 px-2.5 font-medium text-cyan-300">
                      {log.actor_username} ({log.actor_role || 'user'})
                    </td>
                    <td className="py-2 px-2.5 font-mono text-white">{log.action}</td>
                    <td className="py-2 px-2.5 text-slate-300">
                      {log.resource_type}: {log.resource_id || '—'}
                    </td>
                    <td className="py-2 px-2.5">
                      <span
                        className={`px-1.5 py-0.5 rounded font-mono text-[10px] ${
                          log.status === 'success'
                            ? 'bg-emerald-500/15 text-emerald-300'
                            : 'bg-red-500/15 text-red-300'
                        }`}
                      >
                        {log.status}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
};

