import React, { useCallback, useEffect, useState } from 'react';
import {
  Check,
  Code,
  Edit3,
  Power,
  RefreshCw,
  Sliders,
  X,
} from 'lucide-react';
import { api } from '../services/api';
import { DetectionRule } from '../types';
import { SeverityBadge } from '../components/SeverityBadge';
import { formatTimestamp } from '../utils/formatters';

export const DetectionRulesPage: React.FC = () => {
  const [rules, setRules] = useState<DetectionRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [editingRule, setEditingRule] = useState<DetectionRule | null>(null);
  const [editThreshold, setEditThreshold] = useState<number>(5);
  const [editWindow, setEditWindow] = useState<number>(300);
  const [editSeverity, setEditSeverity] = useState<string>('high');
  const [editDescription, setEditDescription] = useState<string>('');
  const [feedback, setFeedback] = useState<string | null>(null);

  const loadRules = useCallback(async () => {
    setLoading(true);
    try {
      const list = await api.listDetectionRules();
      setRules(list);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadRules();
  }, [loadRules]);

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

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-white">
            Detection Rules & Correlation Configuration
          </h1>
          <p className="text-xs text-slate-400">
            Configure rule thresholds, correlation time windows, severities, MITRE ATT&CK mappings, and active status
          </p>
        </div>
        <button
          onClick={loadRules}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-[#0f1623] hover:bg-[#151f32] border border-[#1e2c45] text-slate-200 text-xs self-start"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          Refresh Rules
        </button>
      </div>

      {feedback && (
        <div className="p-3 rounded bg-cyan-500/15 border border-cyan-500/40 text-cyan-200 text-xs flex items-center justify-between">
          <span>{feedback}</span>
          <button onClick={() => setFeedback(null)} className="text-cyan-400 hover:underline">
            Dismiss
          </button>
        </div>
      )}

      {loading ? (
        <div className="soc-panel p-10 text-center text-xs text-slate-400">
          Loading detection rules from PostgreSQL...
        </div>
      ) : (
        <div className="space-y-4">
          {rules.map((rule) => (
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
                      <span className="px-2 py-0.5 rounded bg-blue-500/15 text-blue-300 border border-blue-500/30 font-mono text-[11px]">
                        MITRE {rule.mitre_tactic} • {rule.mitre_technique_id} (
                        {rule.mitre_technique_name})
                      </span>
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
                    className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded font-medium border ${
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

      {/* Edit Rule Configuration Modal */}
      {editingRule && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
          <div className="soc-panel w-full max-w-md p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-[#1e2c45] pb-3">
              <div className="flex items-center gap-2">
                <Sliders className="w-4 h-4 text-cyan-400" />
                <h3 className="text-sm font-semibold text-white">
                  Configure {editingRule.rule_id}: {editingRule.name}
                </h3>
              </div>
              <button
                onClick={() => setEditingRule(null)}
                className="text-slate-400 hover:text-white"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleSaveRuleConfig} className="space-y-3 text-xs">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-400 mb-1">
                    Threshold Count (Events)
                  </label>
                  <input
                    type="number"
                    min={1}
                    max={1000}
                    value={editThreshold}
                    onChange={(e) => setEditThreshold(Number(e.target.value))}
                    className="w-full bg-[#090d16] border border-[#1e2c45] rounded px-3 py-1.5 font-mono text-white"
                    required
                  />
                </div>
                <div>
                  <label className="block text-slate-400 mb-1">
                    Correlation Window (Seconds)
                  </label>
                  <input
                    type="number"
                    min={10}
                    max={86400}
                    value={editWindow}
                    onChange={(e) => setEditWindow(Number(e.target.value))}
                    className="w-full bg-[#090d16] border border-[#1e2c45] rounded px-3 py-1.5 font-mono text-white"
                    required
                  />
                </div>
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Alert Severity</label>
                <select
                  value={editSeverity}
                  onChange={(e) => setEditSeverity(e.target.value)}
                  className="w-full bg-[#090d16] border border-[#1e2c45] rounded px-3 py-1.5 text-white"
                >
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                </select>
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Rule Description</label>
                <textarea
                  rows={3}
                  value={editDescription}
                  onChange={(e) => setEditDescription(e.target.value)}
                  className="w-full bg-[#090d16] border border-[#1e2c45] rounded p-2 text-white"
                  required
                />
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setEditingRule(null)}
                  className="px-3 py-1.5 rounded border border-[#1e2c45] text-slate-300"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="inline-flex items-center gap-1 px-4 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-white font-medium"
                >
                  <Check className="w-3.5 h-3.5" />
                  Save Rule Changes
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

