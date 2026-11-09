import React, { useCallback, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  ExternalLink,
  Play,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Zap,
} from 'lucide-react';
import { api } from '../services/api';
import { TelemetryScenario } from '../types';
import { AlertStatusBadge, SeverityBadge } from '../components/SeverityBadge';
import { formatTimestamp } from '../utils/formatters';

export const ThreatDetectionPage: React.FC = () => {
  const navigate = useNavigate();
  const [mitreData, setMitreData] = useState<any | null>(null);
  const [scenarios, setScenarios] = useState<TelemetryScenario[]>([]);
  const [loading, setLoading] = useState(true);
  const [simulatingId, setSimulatingId] = useState<string | null>(null);
  const [lastSimBanner, setLastSimBanner] = useState<string | null>(null);
  const [selectedTactic, setSelectedTactic] = useState<string>('all');

  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      const [mData, scenList] = await Promise.all([
        api.getMitreMappings(),
        api.listTelemetryScenarios(),
      ]);
      setMitreData(mData);
      setScenarios(scenList);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const handleRunScenario = async (scenarioId: string) => {
    setSimulatingId(scenarioId);
    setLastSimBanner(null);
    try {
      const res = await api.simulateScenario(scenarioId, 1);
      setLastSimBanner(
        `Simulated scenario '${scenarioId}': Ingested ${res.accepted_count} synthetic events and generated ${res.generated_alerts_count} new alert(s).`
      );
      await loadData();
    } finally {
      setSimulatingId(null);
    }
  };

  const handleEvaluateNow = async () => {
    setSimulatingId('evaluate');
    try {
      const res = await api.evaluateDetectionsNow();
      setLastSimBanner(
        `Evaluated ${res.evaluated_events_count} events across active detection rules (${res.new_alerts_generated} new alert(s)).`
      );
      await loadData();
    } finally {
      setSimulatingId(null);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-white">
            Threat Detection & MITRE ATT&CK Coverage
          </h1>
          <p className="text-xs text-slate-400">
            Real-time correlation engine mapped to official MITRE ATT&CK tactics, techniques, and synthetic attack verification
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={handleEvaluateNow}
            disabled={simulatingId !== null}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-medium"
          >
            <Zap className="w-3.5 h-3.5" />
            Re-Evaluate Telemetry Window
          </button>
          <button
            onClick={() => navigate('/rules')}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-[#151f32] hover:bg-[#1e2c45] border border-[#243554] text-slate-200 text-xs"
          >
            Configure Rule Thresholds →
          </button>
        </div>
      </div>

      {lastSimBanner && (
        <div className="p-3 rounded bg-cyan-500/15 border border-cyan-500/40 text-cyan-200 text-xs flex items-center justify-between">
          <span>{lastSimBanner}</span>
          <button onClick={() => setLastSimBanner(null)} className="text-cyan-400 hover:underline">
            Dismiss
          </button>
        </div>
      )}

      {/* Synthetic Attack & Traffic Simulation Lab */}
      <div className="soc-panel p-4 space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-sm font-semibold text-white">
              Live Synthetic Attack & Traffic Simulation Matrix
            </h2>
            <p className="text-[11px] text-slate-400">
              Trigger reproducible synthetic security telemetry scenarios to verify rule detection accuracy in real time
            </p>
          </div>
          <button
            onClick={() => handleRunScenario('all')}
            disabled={simulatingId !== null}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-red-600/90 hover:bg-red-500 text-white text-xs font-medium"
          >
            <Play className="w-3.5 h-3.5" />
            {simulatingId === 'all' ? 'Simulating Full Suite...' : 'Execute All 9 Scenarios'}
          </button>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          {scenarios.map((scen) => (
            <div
              key={scen.id}
              className="p-3 rounded bg-[#151f32] border border-[#1e2c45] flex flex-col justify-between gap-2 text-xs"
            >
              <div className="space-y-1">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-white">{scen.name}</span>
                  {scen.is_attack ? (
                    <span className="px-1.5 py-0.5 rounded bg-red-500/15 text-red-300 border border-red-500/30 font-mono text-[10px]">
                      {scen.expected_rule_id} • {scen.mitre_technique_id}
                    </span>
                  ) : (
                    <span className="px-1.5 py-0.5 rounded bg-emerald-500/15 text-emerald-300 border border-emerald-500/30 font-mono text-[10px]">
                      BENIGN BASELINE
                    </span>
                  )}
                </div>
                <p className="text-[11px] text-slate-400">{scen.description}</p>
              </div>
              <div className="flex items-center justify-between pt-2 border-t border-[#1e2c45]">
                <span className="text-[10px] font-mono text-slate-400">
                  Category: {scen.category}
                </span>
                <button
                  onClick={() => handleRunScenario(scen.id)}
                  disabled={simulatingId !== null}
                  className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-[#090d16] hover:bg-cyan-500/20 border border-cyan-500/40 text-cyan-300 text-[11px] font-medium"
                >
                  <Play className="w-3 h-3" />
                  {simulatingId === scen.id ? 'Running...' : 'Simulate'}
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* MITRE ATT&CK Technique & Rule Coverage Cards */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-sm font-semibold text-white">
              MITRE ATT&CK Framework Detection Mapping
            </h2>
            <p className="text-[11px] text-slate-400">
              Official Tactic, Technique ID, Technique Name, associated Detection Rule, and correlated Alerts
            </p>
          </div>
          <button
            onClick={loadData}
            className="inline-flex items-center gap-1 text-xs text-cyan-400 hover:underline"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Refresh Mappings
          </button>
        </div>

        {loading || !mitreData ? (
          <div className="soc-panel p-8 text-center text-xs text-slate-400">
            Loading MITRE ATT&CK coverage matrix...
          </div>
        ) : (
          <>
            {/* MITRE Tactic Summary Strip */}
            {mitreData.tactic_summary && mitreData.tactic_summary.length > 0 && (
              <div className="flex flex-wrap items-center gap-2">
                <button
                  onClick={() => setSelectedTactic('all')}
                  className={`px-3 py-1.5 rounded text-xs font-medium border transition-colors ${
                    selectedTactic === 'all'
                      ? 'bg-cyan-500/20 border-cyan-400 text-cyan-200'
                      : 'bg-[#0f1623] border-[#1e2c45] text-slate-300 hover:border-cyan-500/40'
                  }`}
                >
                  All Tactics ({mitreData.total_mapped_rules})
                </button>
                {mitreData.tactic_summary.map((ts: any) => (
                  <button
                    key={ts.tactic}
                    onClick={() => setSelectedTactic(ts.tactic)}
                    className={`px-3 py-1.5 rounded text-xs font-medium border transition-colors flex items-center gap-2 ${
                      selectedTactic === ts.tactic
                        ? 'bg-cyan-500/20 border-cyan-400 text-cyan-200'
                        : 'bg-[#0f1623] border-[#1e2c45] text-slate-300 hover:border-cyan-500/40'
                    }`}
                  >
                    <span>
                      {ts.tactic_id ? `${ts.tactic_id} • ` : ''}
                      {ts.tactic}
                    </span>
                    <span className="px-1.5 py-0.5 rounded bg-[#090d16] font-mono text-[10px] text-cyan-400">
                      {ts.alert_count} alert(s)
                    </span>
                  </button>
                ))}
              </div>
            )}

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              {mitreData.mappings
                .filter(
                  (m: any) => selectedTactic === 'all' || m.tactic === selectedTactic
                )
                .map((m: any) => {
                  const rulesList =
                    m.associated_rules && m.associated_rules.length > 0
                      ? m.associated_rules
                      : m.rule
                      ? [m.rule]
                      : [];
                  return (
                    <div key={m.rule.rule_id} className="soc-panel p-4 space-y-3">
                      <div className="flex items-start justify-between gap-2">
                        <div>
                          <div className="flex flex-wrap items-center gap-2">
                            <span className="px-2 py-0.5 rounded bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 font-mono text-xs font-bold">
                              {m.technique_id}
                            </span>
                            <span className="px-2 py-0.5 rounded bg-blue-500/15 text-blue-300 border border-blue-500/30 text-xs font-semibold uppercase tracking-wider">
                              {m.tactic_id ? `${m.tactic_id} • ` : ''}
                              {m.tactic}
                            </span>
                          </div>
                          <h3 className="text-sm font-bold text-white mt-1.5">
                            {m.technique_name}
                          </h3>
                        </div>
                        <a
                          href={m.reference_url}
                          target="_blank"
                          rel="noreferrer"
                          className="inline-flex items-center gap-1 text-[11px] text-cyan-400 hover:underline shrink-0"
                        >
                          MITRE Ref
                          <ExternalLink className="w-3 h-3" />
                        </a>
                      </div>

                      {/* Associated Detection Rules */}
                      <div className="space-y-1.5">
                        <div className="text-[11px] text-slate-400 font-medium">
                          Associated Detection Rules ({rulesList.length})
                        </div>
                        {rulesList.map((r: any) => (
                          <div
                            key={r.rule_id}
                            className="p-3 rounded bg-[#151f32] border border-[#1e2c45] flex items-center justify-between text-xs"
                          >
                            <div>
                              <div className="flex items-center gap-2">
                                <span className="font-mono text-cyan-400 font-semibold">
                                  {r.rule_id}
                                </span>
                                <span className="text-slate-100 font-medium">{r.name}</span>
                              </div>
                              <div className="text-[11px] text-slate-400 mt-0.5">
                                Threshold: ≥ {r.threshold_count} events within{' '}
                                {r.time_window_seconds}s window
                              </div>
                            </div>
                            <div className="flex items-center gap-2">
                              <SeverityBadge severity={r.severity} />
                              {r.enabled ? (
                                <span className="inline-flex items-center gap-1 text-emerald-400 text-[11px]">
                                  <ShieldCheck className="w-3.5 h-3.5" />
                                  Enabled
                                </span>
                              ) : (
                                <span className="inline-flex items-center gap-1 text-slate-500 text-[11px]">
                                  <ShieldAlert className="w-3.5 h-3.5" />
                                  Disabled
                                </span>
                              )}
                            </div>
                          </div>
                        ))}
                      </div>

                      {/* Related Alerts */}
                      <div className="space-y-1.5">
                        <div className="flex items-center justify-between text-[11px] text-slate-400">
                          <span>Related Alerts ({m.alert_count})</span>
                          {m.alert_count > 0 && (
                            <button
                              onClick={() => navigate(`/alerts?rule_code=${m.rule.rule_id}`)}
                              className="text-cyan-400 hover:underline"
                            >
                              Filter in Alerts →
                            </button>
                          )}
                        </div>
                        {m.related_alerts.length === 0 ? (
                          <div className="text-[11px] text-slate-500 italic">
                            No active alerts triggered for this technique yet.
                          </div>
                        ) : (
                          <div className="space-y-1">
                            {m.related_alerts.slice(0, 3).map((al: any) => (
                              <div
                                key={al.id}
                                onClick={() => navigate(`/alerts?alertId=${al.id}`)}
                                className="p-2 rounded bg-[#090d16] border border-[#1e2c45] hover:border-cyan-500/40 cursor-pointer flex items-center justify-between text-xs"
                              >
                                <div className="truncate pr-2">
                                  <span className="font-mono text-cyan-400 mr-2">{al.alert_id}</span>
                                  <span className="text-slate-200">{al.title}</span>
                                </div>
                                <div className="flex items-center gap-2 shrink-0">
                                  <span className="font-mono text-[10px] text-slate-400">
                                    {formatTimestamp(al.last_seen)}
                                  </span>
                                  <AlertStatusBadge status={al.status} />
                                </div>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    </div>
                  );
                })}
            </div>
          </>
        )}
      </div>
    </div>
  );
};

