import React, { useCallback, useEffect, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import {
  Check,
  Code,
  Edit3,
  ExternalLink,
  Filter,
  Play,
  Power,
  RefreshCw,
  Search,
  ShieldAlert,
  ShieldCheck,
  Sliders,
  X,
  Zap,
} from 'lucide-react';
import { api } from '../services/api';
import { DetectionRule, TelemetryScenario } from '../types';
import { AlertStatusBadge, SeverityBadge } from '../components/SeverityBadge';
import { formatTimestamp } from '../utils/formatters';

export const DetectionRulesPage: React.FC = () => {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();

  // Active view tab: 'rules' or 'mitre'
  const currentTab = searchParams.get('tab') === 'mitre' ? 'mitre' : 'rules';
  const setTab = (tab: 'rules' | 'mitre') => {
    setSearchParams({ tab });
  };

  // Rules Inventory State
  const [rules, setRules] = useState<DetectionRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [ruleTacticFilter, setRuleTacticFilter] = useState('all');

  // Edit Rule Modal State
  const [editingRule, setEditingRule] = useState<DetectionRule | null>(null);
  const [editThreshold, setEditThreshold] = useState<number>(5);
  const [editWindow, setEditWindow] = useState<number>(300);
  const [editSeverity, setEditSeverity] = useState<string>('high');
  const [editDescription, setEditDescription] = useState<string>('');
  const [feedback, setFeedback] = useState<string | null>(null);

  // MITRE ATT&CK Matrix State
  const [mitreData, setMitreData] = useState<any | null>(null);
  const [scenarios, setScenarios] = useState<TelemetryScenario[]>([]);
  const [selectedMitreTactic, setSelectedMitreTactic] = useState<string>('all');
  const [simulatingId, setSimulatingId] = useState<string | null>(null);
  const [lastSimBanner, setLastSimBanner] = useState<string | null>(null);

  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      const [ruleList, mData, scenList] = await Promise.all([
        Promise.resolve(api.listDetectionRules ? api.listDetectionRules() : []),
        Promise.resolve(api.getMitreMappings ? api.getMitreMappings() : null).catch(() => null),
        Promise.resolve(api.listTelemetryScenarios ? api.listTelemetryScenarios() : []).catch(() => []),
      ]);
      setRules(Array.isArray(ruleList) ? ruleList : []);
      setMitreData(mData);
      setScenarios(Array.isArray(scenList) ? scenList : []);
    } catch {
      setRules([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const handleToggleRule = async (rule: DetectionRule) => {
    setFeedback(null);
    try {
      const updated = await api.updateDetectionRule(rule.rule_id, {
        enabled: !rule.enabled,
      });
      setRules((prev) => prev.map((r) => (r.id === updated.id ? updated : r)));
      setFeedback(
        `Rule ${updated.rule_id} (${updated.name}) ${
          updated.enabled ? 'ENABLED' : 'DISABLED'
        }.`
      );
    } catch (err: any) {
      setFeedback(`Error: ${err.message}`);
    }
  };

  const openEditModal = (rule: DetectionRule) => {
    setEditingRule(rule);
    setEditThreshold(rule.threshold_count);
    setEditWindow(rule.time_window_seconds);
    setEditSeverity(rule.severity);
    setEditDescription(rule.description);
  };

  const handleSaveRuleConfig = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editingRule) return;
    try {
      const updated = await api.updateDetectionRule(editingRule.rule_id, {
        threshold_count: Number(editThreshold),
        time_window_seconds: Number(editWindow),
        severity: editSeverity,
        description: editDescription,
      });
      setRules((prev) => prev.map((r) => (r.id === updated.id ? updated : r)));
      setEditingRule(null);
      setFeedback(`Saved threshold & window configuration for ${updated.rule_id}.`);
    } catch (err: any) {
      setFeedback(`Error: ${err.message}`);
    }
  };

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

  // Filtered rules
  const filteredRules = rules.filter((r) => {
    const matchesSearch =
      r.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      r.rule_id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      r.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (r.mitre_technique_id && r.mitre_technique_id.toLowerCase().includes(searchQuery.toLowerCase()));
    const matchesTactic =
      ruleTacticFilter === 'all' ||
      (r.mitre_tactic && r.mitre_tactic.toLowerCase() === ruleTacticFilter.toLowerCase());
    return matchesSearch && matchesTactic;
  });

  // Unique tactics for filter dropdown
  const uniqueTactics = Array.from(
    new Set(rules.map((r) => r.mitre_tactic).filter((t): t is string => Boolean(t)))
  );

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-white">
            Threat Detection Rules & MITRE ATT&CK Framework
          </h1>
          <p className="text-xs text-slate-400">
            Configure correlation rules, thresholds, sliding time windows, and evaluate real-time MITRE ATT&CK tactical coverage
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={handleEvaluateNow}
            disabled={simulatingId !== null}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-medium"
            title="Re-run active detection window across recent security events"
          >
            <Zap className="w-3.5 h-3.5" />
            {simulatingId === 'evaluate' ? 'Evaluating...' : 'Re-Evaluate Window'}
          </button>
          <button
            onClick={loadData}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-[#0f1623] hover:bg-[#151f32] border border-[#1e2c45] text-slate-200 text-xs"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Refresh
          </button>
        </div>
      </div>

      {/* Primary Sub-Navigation Tabs */}
      <div className="flex items-center gap-2 border-b border-[#1e2c45] pb-2">
        <button
          onClick={() => setTab('rules')}
          className={`flex items-center gap-2 px-4 py-2 rounded text-xs font-semibold transition-all ${
            currentTab === 'rules'
              ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/40'
              : 'text-slate-400 hover:text-slate-200 hover:bg-[#151f32]'
          }`}
        >
          <Sliders className="w-4 h-4" />
          Detection Rules Inventory ({rules.length})
        </button>
        <button
          onClick={() => setTab('mitre')}
          className={`flex items-center gap-2 px-4 py-2 rounded text-xs font-semibold transition-all ${
            currentTab === 'mitre'
              ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/40'
              : 'text-slate-400 hover:text-slate-200 hover:bg-[#151f32]'
          }`}
        >
          <ShieldAlert className="w-4 h-4" />
          MITRE ATT&CK Coverage Matrix
        </button>
      </div>

      {/* Feedback Banner */}
      {feedback && (
        <div className="p-3 rounded bg-cyan-500/15 border border-cyan-500/40 text-cyan-200 text-xs flex items-center justify-between">
          <span>{feedback}</span>
          <button onClick={() => setFeedback(null)} className="text-cyan-400 hover:underline">
            Dismiss
          </button>
        </div>
      )}

      {/* Simulation Banner */}
      {lastSimBanner && (
        <div className="p-3 rounded bg-blue-500/15 border border-blue-500/40 text-blue-200 text-xs flex items-center justify-between">
          <span>{lastSimBanner}</span>
          <button onClick={() => setLastSimBanner(null)} className="text-blue-400 hover:underline">
            Dismiss
          </button>
        </div>
      )}

      {/* TAB 1: Detection Rules Inventory */}
      {currentTab === 'rules' && (
        <div className="space-y-4">
          {/* Rules Search and Tactic Filter Bar */}
          <div className="soc-panel p-3 flex flex-col sm:flex-row items-center justify-between gap-3 text-xs">
            <div className="relative flex-1 w-full sm:w-auto">
              <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-slate-400" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search rule name, rule ID, MITRE technique..."
                className="w-full pl-9 pr-3 py-1.5 bg-[#090d16] border border-[#1e2c45] rounded text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
              />
            </div>
            <div className="flex items-center gap-2 w-full sm:w-auto">
              <Filter className="w-3.5 h-3.5 text-slate-400" />
              <select
                value={ruleTacticFilter}
                onChange={(e) => setRuleTacticFilter(e.target.value)}
                className="bg-[#090d16] border border-[#1e2c45] rounded px-2.5 py-1.5 text-slate-200 focus:outline-none focus:border-cyan-500"
              >
                <option value="all">All MITRE Tactics</option>
                {uniqueTactics.map((t) => (
                  <option key={t} value={t}>
                    {t}
                  </option>
                ))}
              </select>
            </div>
          </div>

          {loading ? (
            <div className="soc-panel p-10 text-center text-xs text-slate-400">
              Loading detection rules from PostgreSQL...
            </div>
          ) : filteredRules.length === 0 ? (
            <div className="soc-panel p-10 text-center text-xs text-slate-400">
              No detection rules matched the current search or tactic filter.
            </div>
          ) : (
            <div className="space-y-4">
              {filteredRules.map((rule) => (
                <div key={rule.id} className="soc-panel p-5 space-y-3 text-xs">
                  <div className="flex flex-col md:flex-row md:items-start justify-between gap-3">
                    <div className="space-y-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-mono text-cyan-400 font-bold text-sm">
                          {rule.rule_id}
                        </span>
                        <SeverityBadge severity={rule.severity} />
                        <span className="px-2 py-0.5 rounded bg-[#151f32] border border-[#243554] text-slate-300 font-mono text-[11px]">
                          Category: {rule.event_category}
                        </span>
                        {rule.mitre_technique_id && (
                          <button
                            type="button"
                            onClick={() => {
                              setTab('mitre');
                              if (rule.mitre_tactic) setSelectedMitreTactic(rule.mitre_tactic);
                            }}
                            className="px-2 py-0.5 rounded bg-blue-500/15 text-blue-300 border border-blue-500/30 font-mono text-[11px] hover:border-blue-400 transition-colors"
                            title="View in MITRE ATT&CK Matrix"
                          >
                            MITRE {rule.mitre_tactic} • {rule.mitre_technique_id} (
                            {rule.mitre_technique_name})
                          </button>
                        )}
                      </div>
                      <h2 className="text-base font-bold text-white pt-1">{rule.name}</h2>
                      <p className="text-slate-300 leading-relaxed">{rule.description}</p>
                    </div>

                    <div className="flex items-center gap-2 shrink-0">
                      <button
                        onClick={() => openEditModal(rule)}
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-[#151f32] hover:bg-[#1e2c45] border border-[#243554] text-slate-200 font-medium"
                      >
                        <Edit3 className="w-3.5 h-3.5 text-cyan-400" />
                        Configure
                      </button>
                      <button
                        onClick={() => handleToggleRule(rule)}
                        className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded font-medium border transition-colors ${
                          rule.enabled
                            ? 'bg-emerald-500/15 text-emerald-300 border-emerald-500/40 hover:bg-emerald-500/25'
                            : 'bg-slate-800 text-slate-400 border-slate-700 hover:bg-slate-700'
                        }`}
                      >
                        <Power className="w-3.5 h-3.5" />
                        {rule.enabled ? 'Enabled' : 'Disabled'}
                      </button>
                    </div>
                  </div>

                  {/* Rule Parameters & Logic */}
                  <div className="grid grid-cols-1 lg:grid-cols-3 gap-3 pt-2">
                    <div className="lg:col-span-2 p-3 rounded bg-[#090d16] border border-[#1e2c45] space-y-1">
                      <div className="flex items-center gap-1.5 text-[11px] font-semibold text-cyan-400">
                        <Code className="w-3.5 h-3.5" />
                        <span>Detection Correlation Logic</span>
                      </div>
                      <pre className="font-mono text-[11px] text-slate-200 whitespace-pre-wrap">
                        {rule.detection_logic}
                      </pre>
                    </div>

                    <div className="p-3 rounded bg-[#151f32] border border-[#243554] grid grid-cols-2 gap-2">
                      <div>
                        <div className="text-[10px] uppercase text-slate-400">Threshold Count</div>
                        <div className="text-base font-bold font-mono text-white">
                          ≥ {rule.threshold_count}
                        </div>
                      </div>
                      <div>
                        <div className="text-[10px] uppercase text-slate-400">Time Window</div>
                        <div className="text-base font-bold font-mono text-cyan-300">
                          {rule.time_window_seconds}s
                        </div>
                      </div>
                      <div>
                        <div className="text-[10px] uppercase text-slate-400">Alerts Triggered</div>
                        <div className="text-sm font-bold font-mono text-orange-300">
                          {rule.alert_count}
                        </div>
                      </div>
                      <div>
                        <div className="text-[10px] uppercase text-slate-400">Last Updated</div>
                        <div className="text-[11px] font-mono text-slate-300">
                          {formatTimestamp(rule.updated_at).slice(0, 10)}
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* TAB 2: MITRE ATT&CK Matrix & Coverage View */}
      {currentTab === 'mitre' && (
        <div className="space-y-6">
          {/* Synthetic Attack & Traffic Simulation Lab */}
          <div className="soc-panel p-4 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div>
                <h2 className="text-sm font-semibold text-white">
                  Synthetic Attack & Traffic Simulation Matrix
                </h2>
                <p className="text-[11px] text-slate-400">
                  Trigger reproducible synthetic security telemetry scenarios to verify rule detection accuracy in real time
                </p>
              </div>
              <button
                onClick={() => handleRunScenario('all')}
                disabled={simulatingId !== null}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-red-600/90 hover:bg-red-500 text-white text-xs font-medium self-start sm:self-auto"
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

          {/* MITRE ATT&CK Matrix Cards */}
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-sm font-semibold text-white">
                  MITRE ATT&CK Framework Tactical Coverage
                </h2>
                <p className="text-[11px] text-slate-400">
                  Official Tactic, Technique ID, Technique Name, associated Detection Rule, and correlated Alerts
                </p>
              </div>
            </div>

            {loading || !mitreData ? (
              <div className="soc-panel p-8 text-center text-xs text-slate-400">
                Loading MITRE ATT&CK coverage matrix...
              </div>
            ) : (
              <>
                {/* Tactic Filter Buttons */}
                {mitreData.tactic_summary && mitreData.tactic_summary.length > 0 && (
                  <div className="flex flex-wrap items-center gap-2">
                    <button
                      onClick={() => setSelectedMitreTactic('all')}
                      className={`px-3 py-1.5 rounded text-xs font-medium border transition-colors ${
                        selectedMitreTactic === 'all'
                          ? 'bg-cyan-500/20 border-cyan-400 text-cyan-200'
                          : 'bg-[#0f1623] border-[#1e2c45] text-slate-300 hover:border-cyan-500/40'
                      }`}
                    >
                      All Tactics ({mitreData.total_mapped_rules})
                    </button>
                    {mitreData.tactic_summary.map((ts: any) => (
                      <button
                        key={ts.tactic}
                        onClick={() => setSelectedMitreTactic(ts.tactic)}
                        className={`px-3 py-1.5 rounded text-xs font-medium border transition-colors flex items-center gap-2 ${
                          selectedMitreTactic === ts.tactic
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
                      (m: any) =>
                        selectedMitreTactic === 'all' || m.tactic === selectedMitreTactic
                    )
                    .map((m: any) => {
                      const rulesList =
                        m.associated_rules && m.associated_rules.length > 0
                          ? m.associated_rules
                          : m.rule
                          ? [m.rule]
                          : [];
                      return (
                        <div key={m.rule.rule_id} className="soc-panel p-4 space-y-3 text-xs">
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
                            {m.reference_url && (
                              <a
                                href={m.reference_url}
                                target="_blank"
                                rel="noreferrer"
                                className="inline-flex items-center gap-1 text-[11px] text-cyan-400 hover:underline shrink-0"
                              >
                                MITRE Ref
                                <ExternalLink className="w-3 h-3" />
                              </a>
                            )}
                          </div>

                          {/* Associated Rules */}
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
                                      <span className="font-mono text-cyan-400 mr-2">
                                        {al.alert_id}
                                      </span>
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
      )}

      {/* Edit Rule Thresholds & Parameters Modal */}
      {editingRule && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm animate-fade-in">
          <div className="soc-panel w-full max-w-lg p-6 space-y-4 text-xs bg-[#0b101b] border border-[#243554] shadow-2xl rounded-lg">
            <div className="flex items-center justify-between border-b border-[#1e2c45] pb-3">
              <div>
                <div className="font-mono text-cyan-400 font-bold">{editingRule.rule_id}</div>
                <h3 className="text-sm font-bold text-white mt-0.5">{editingRule.name}</h3>
              </div>
              <button
                onClick={() => setEditingRule(null)}
                className="p-1 rounded text-slate-400 hover:text-white"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleSaveRuleConfig} className="space-y-4">
              <div>
                <label className="block text-slate-300 font-medium mb-1">
                  Threshold Count (Minimum Events Required)
                </label>
                <input
                  type="number"
                  min={1}
                  max={100}
                  value={editThreshold}
                  onChange={(e) => setEditThreshold(Number(e.target.value))}
                  className="w-full bg-[#090d16] border border-[#1e2c45] rounded p-2 text-white font-mono"
                  required
                />
                <p className="text-[10px] text-slate-500 mt-1">
                  How many matched security events are required before firing an alert.
                </p>
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">
                  Time Window (Seconds)
                </label>
                <input
                  type="number"
                  min={10}
                  max={86400}
                  value={editWindow}
                  onChange={(e) => setEditWindow(Number(e.target.value))}
                  className="w-full bg-[#090d16] border border-[#1e2c45] rounded p-2 text-white font-mono"
                  required
                />
                <p className="text-[10px] text-slate-500 mt-1">
                  Sliding window in seconds: e.g. 300 = 5 minutes, 600 = 10 minutes.
                </p>
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">Alert Severity</label>
                <select
                  value={editSeverity}
                  onChange={(e) => setEditSeverity(e.target.value)}
                  className="w-full bg-[#090d16] border border-[#1e2c45] rounded p-2 text-white"
                >
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                </select>
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">Rule Description</label>
                <textarea
                  rows={3}
                  value={editDescription}
                  onChange={(e) => setEditDescription(e.target.value)}
                  className="w-full bg-[#090d16] border border-[#1e2c45] rounded p-2 text-white"
                />
              </div>

              <div className="flex items-center justify-end gap-2 pt-2 border-t border-[#1e2c45]">
                <button
                  type="button"
                  onClick={() => setEditingRule(null)}
                  className="px-3 py-1.5 rounded bg-[#151f32] hover:bg-[#1e2c45] text-slate-300"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-white font-medium flex items-center gap-1.5"
                >
                  <Check className="w-3.5 h-3.5" />
                  Save Rule Parameters
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
