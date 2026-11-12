import React, { useCallback, useEffect, useState } from 'react';
import {
  CheckCircle,
  Download,
  FileSpreadsheet,
  FileText,
  RefreshCw,
  Target,
} from 'lucide-react';
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { api } from '../services/api';
import { IncidentStatusBadge, SeverityBadge } from './SeverityBadge';

const RESOLUTION_COLORS = ['#f97316', '#10b981', '#64748b'];

export const AnalyticsReportsSection: React.FC = () => {
  const [report, setReport] = useState<any | null>(null);
  const [loading, setLoading] = useState(true);

  const loadReport = useCallback(async () => {
    setLoading(true);
    try {
      const res = await api.getAnalyticsPerformance();
      setReport(res);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadReport();
  }, [loadReport]);

  if (loading || !report) {
    return (
      <div className="soc-panel p-12 text-center text-xs text-slate-400">
        Computing analytical metrics and ground-truth detection evaluation...
      </div>
    );
  }

  const evalData = report.detection_evaluation;

  return (
    <div className="space-y-6">
      {/* Header & Export Buttons */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h2 className="text-base font-bold text-white">
            Security Analytics, Rule Efficacy & Executive Reports
          </h2>
          <p className="text-xs text-slate-400">
            Rule efficacy metrics (Precision, Recall, F1 Score on labeled synthetic data), resolution posture, and CSV/PDF exports
          </p>
        </div>
        <div className="flex items-center gap-2">
          <a
            href={api.getCsvReportUrl()}
            download
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-[#151f32] hover:bg-[#1e2c45] border border-cyan-500/40 text-cyan-300 text-xs font-medium"
          >
            <FileSpreadsheet className="w-3.5 h-3.5" />
            Export CSV Report
          </a>
          <a
            href={api.getPdfReportUrl()}
            download
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-medium"
          >
            <FileText className="w-3.5 h-3.5" />
            Export PDF Report
          </a>
          <button
            onClick={loadReport}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-[#0f1623] hover:bg-[#151f32] border border-[#1e2c45] text-slate-200 text-xs"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Recalculate
          </button>
        </div>
      </div>

      {/* Detection Evaluation Metrics (Labeled Ground-Truth Telemetry) */}
      <div className="soc-panel p-5 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-[#1e2c45] pb-3">
          <div>
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              <Target className="w-4 h-4 text-cyan-400" />
              Detection Rule Evaluation Metrics (Labeled Ground-Truth Telemetry)
            </h3>
            <p className="text-[11px] text-slate-400">
              Calculated strictly over ground-truth labeled synthetic security events ({evalData.labeled_events_count} labeled events evaluated)
            </p>
          </div>
          {evalData.has_labeled_data ? (
            <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-emerald-500/15 text-emerald-300 border border-emerald-500/30 text-xs font-mono">
              <CheckCircle className="w-3.5 h-3.5" />
              LABELED DATASET VERIFIED ({evalData.labeled_events_count} EVENTS)
            </span>
          ) : (
            <span className="px-2.5 py-1 rounded bg-yellow-500/15 text-yellow-300 border border-yellow-500/30 text-xs">
              No Labeled Test Telemetry Available
            </span>
          )}
        </div>

        {evalData.has_labeled_data ? (
          <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-3 text-xs">
            <div className="p-3 rounded bg-[#151f32] border border-emerald-500/30">
              <div className="text-[10px] uppercase text-slate-400">True Positives (TP)</div>
              <div className="text-xl font-bold font-mono text-emerald-400 mt-1">
                {evalData.true_positives}
              </div>
              <div className="text-[10px] text-slate-400">Attack events detected</div>
            </div>
            <div className="p-3 rounded bg-[#151f32] border border-red-500/30">
              <div className="text-[10px] uppercase text-slate-400">False Positives (FP)</div>
              <div className="text-xl font-bold font-mono text-red-400 mt-1">
                {evalData.false_positives}
              </div>
              <div className="text-[10px] text-slate-400">Benign events flagged</div>
            </div>
            <div className="p-3 rounded bg-[#151f32] border border-cyan-500/30">
              <div className="text-[10px] uppercase text-slate-400">True Negatives (TN)</div>
              <div className="text-xl font-bold font-mono text-cyan-300 mt-1">
                {evalData.true_negatives}
              </div>
              <div className="text-[10px] text-slate-400">Benign events ignored</div>
            </div>
            <div className="p-3 rounded bg-[#151f32] border border-orange-500/30">
              <div className="text-[10px] uppercase text-slate-400">False Negatives (FN)</div>
              <div className="text-xl font-bold font-mono text-orange-400 mt-1">
                {evalData.false_negatives}
              </div>
              <div className="text-[10px] text-slate-400">Missed attack events</div>
            </div>
            <div className="p-3 rounded bg-[#090d16] border border-[#243554]">
              <div className="text-[10px] uppercase text-slate-400">Precision</div>
              <div className="text-xl font-bold font-mono text-white mt-1">
                {evalData.precision !== null
                  ? `${(evalData.precision * 100).toFixed(1)}%`
                  : 'N/A'}
              </div>
              <div className="text-[10px] text-cyan-400 font-mono">TP / (TP + FP)</div>
            </div>
            <div className="p-3 rounded bg-[#090d16] border border-[#243554]">
              <div className="text-[10px] uppercase text-slate-400">Recall</div>
              <div className="text-xl font-bold font-mono text-white mt-1">
                {evalData.recall !== null ? `${(evalData.recall * 100).toFixed(1)}%` : 'N/A'}
              </div>
              <div className="text-[10px] text-cyan-400 font-mono">TP / (TP + FN)</div>
            </div>
            <div className="p-3 rounded bg-[#090d16] border border-cyan-500/50">
              <div className="text-[10px] uppercase text-cyan-300 font-semibold">F1 Score</div>
              <div className="text-xl font-bold font-mono text-cyan-400 mt-1">
                {evalData.f1_score !== null
                  ? `${(evalData.f1_score * 100).toFixed(1)}%`
                  : 'N/A'}
              </div>
              <div className="text-[10px] text-slate-400 font-mono">Harmonic Mean</div>
            </div>
            <div className="p-3 rounded bg-[#090d16] border border-emerald-500/50">
              <div className="text-[10px] uppercase text-emerald-300 font-semibold">Accuracy</div>
              <div className="text-xl font-bold font-mono text-emerald-400 mt-1">
                {evalData.accuracy !== null && evalData.accuracy !== undefined
                  ? `${(evalData.accuracy * 100).toFixed(1)}%`
                  : 'N/A'}
              </div>
              <div className="text-[10px] text-slate-400 font-mono">(TP+TN) / Total</div>
            </div>
          </div>
        ) : (
          <div className="p-6 text-center text-xs text-slate-400">
            No labeled ground-truth telemetry is currently stored. Run a synthetic simulation scenario to evaluate TP, FP, TN, FN, Precision, Recall, and F1 Score.
          </div>
        )}
      </div>

      {/* Charts Row: Most Frequent Rules, Resolved vs Unresolved Alerts, Auth Trends */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Most Frequent Detection Rules */}
        <div className="soc-panel p-4">
          <div className="mb-3">
            <h3 className="text-sm font-semibold text-white">Most Frequent Detection Rules</h3>
            <p className="text-[11px] text-slate-400">
              Alert volume generated per correlation rule
            </p>
          </div>
          <div className="h-60">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={report.most_frequent_rules} layout="vertical">
                <CartesianGrid strokeDasharray="3 3" stroke="#1e2c45" />
                <XAxis type="number" stroke="#94a3b8" fontSize={11} allowDecimals={false} />
                <YAxis dataKey="rule_id" type="category" stroke="#94a3b8" fontSize={11} width={72} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0f1623',
                    borderColor: '#243554',
                    fontSize: '12px',
                  }}
                />
                <Bar dataKey="alerts_generated" name="Alerts" fill="#06b6d4" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Resolved vs Unresolved Alerts */}
        <div className="soc-panel p-4">
          <div className="mb-3">
            <h3 className="text-sm font-semibold text-white">
              Resolved vs. Unresolved Alerts
            </h3>
            <p className="text-[11px] text-slate-400">
              Current SOC triage backlog versus closed alerts
            </p>
          </div>
          <div className="h-60">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={report.resolved_vs_unresolved}
                  dataKey="count"
                  nameKey="status"
                  cx="50%"
                  cy="50%"
                  outerRadius={78}
                  label={{ fontSize: 11, fill: '#e2e8f0' }}
                >
                  {report.resolved_vs_unresolved.map((_: any, index: number) => (
                    <Cell
                      key={index}
                      fill={RESOLUTION_COLORS[index % RESOLUTION_COLORS.length]}
                    />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0f1623',
                    borderColor: '#243554',
                    fontSize: '12px',
                  }}
                />
                <Legend wrapperStyle={{ fontSize: '11px' }} />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Authentication Trends */}
        <div className="soc-panel p-4">
          <div className="mb-3">
            <h3 className="text-sm font-semibold text-white">Authentication Trends</h3>
            <p className="text-[11px] text-slate-400">
              Time-series login success vs. credential failure spikes
            </p>
          </div>
          <div className="h-60">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={report.auth_trends}>
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
                <Bar dataKey="auth_failure" name="Failures" fill="#ef4444" />
                <Bar dataKey="auth_success" name="Success" fill="#10b981" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Incident Resolution Statistics & Alerts by Severity Row */}
      {report.incident_resolution_stats && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="soc-panel p-5 lg:col-span-2 space-y-4">
            <div className="flex items-center justify-between border-b border-[#1e2c45] pb-2.5">
              <div>
                <h3 className="text-sm font-semibold text-white">
                  Incident Resolution Statistics
                </h3>
                <p className="text-[11px] text-slate-400">
                  Real-time incident lifecycle metrics across Open, Investigating, Contained, Resolved, and Closed states
                </p>
              </div>
              <span className="font-mono text-xs text-emerald-400">
                Resolution Rate:{' '}
                {((report.incident_resolution_stats.resolution_rate || 0) * 100).toFixed(1)}%
              </span>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-2.5 text-xs">
              <div className="p-2.5 rounded bg-[#151f32] border border-[#243554]">
                <div className="text-[10px] text-slate-400 uppercase">Total Incidents</div>
                <div className="text-lg font-bold font-mono text-white mt-0.5">
                  {report.incident_resolution_stats.total_incidents}
                </div>
              </div>
              <div className="p-2.5 rounded bg-[#151f32] border border-red-500/30">
                <div className="text-[10px] text-slate-400 uppercase">Open</div>
                <div className="text-lg font-bold font-mono text-red-400 mt-0.5">
                  {report.incident_resolution_stats.open_incidents}
                </div>
              </div>
              <div className="p-2.5 rounded bg-[#151f32] border border-orange-500/30">
                <div className="text-[10px] text-slate-400 uppercase">Investigating</div>
                <div className="text-lg font-bold font-mono text-orange-400 mt-0.5">
                  {report.incident_resolution_stats.investigating_incidents}
                </div>
              </div>
              <div className="p-2.5 rounded bg-[#151f32] border border-yellow-500/30">
                <div className="text-[10px] text-slate-400 uppercase">Contained</div>
                <div className="text-lg font-bold font-mono text-yellow-300 mt-0.5">
                  {report.incident_resolution_stats.contained_incidents}
                </div>
              </div>
              <div className="p-2.5 rounded bg-[#151f32] border border-emerald-500/30">
                <div className="text-[10px] text-slate-400 uppercase">Resolved</div>
                <div className="text-lg font-bold font-mono text-emerald-400 mt-0.5">
                  {report.incident_resolution_stats.resolved_incidents}
                </div>
              </div>
              <div className="p-2.5 rounded bg-[#151f32] border border-cyan-500/30">
                <div className="text-[10px] text-slate-400 uppercase">Closed</div>
                <div className="text-lg font-bold font-mono text-cyan-300 mt-0.5">
                  {report.incident_resolution_stats.closed_incidents}
                </div>
              </div>
              <div className="p-2.5 rounded bg-[#090d16] border border-[#243554]">
                <div className="text-[10px] text-slate-400 uppercase">MTTR</div>
                <div className="text-sm font-bold font-mono text-cyan-300 mt-1">
                  {report.incident_resolution_stats.mean_time_to_resolve_minutes !== null &&
                  report.incident_resolution_stats.mean_time_to_resolve_minutes !== undefined
                    ? `${report.incident_resolution_stats.mean_time_to_resolve_minutes}m`
                    : 'N/A'}
                </div>
              </div>
            </div>
          </div>

          {/* Alerts by Severity Breakdown */}
          <div className="soc-panel p-4 space-y-3">
            <div>
              <h3 className="text-sm font-semibold text-white">Alerts by Severity</h3>
              <p className="text-[11px] text-slate-400">
                Current alert distribution across severity levels
              </p>
            </div>
            <div className="grid grid-cols-2 gap-2.5 text-xs">
              {(report.alerts_by_severity || []).map((item: any) => (
                <div
                  key={item.key}
                  className="p-3 rounded bg-[#151f32] border border-[#243554] flex items-center justify-between"
                >
                  <SeverityBadge severity={item.key} />
                  <span className="text-lg font-bold font-mono text-white">{item.count}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Incident Investigation Reports Table */}
      {Array.isArray(report.incidents_summary) && report.incidents_summary.length > 0 && (
        <div className="soc-panel overflow-hidden">
          <div className="p-4 border-b border-[#1e2c45] flex items-center justify-between">
            <div>
              <h3 className="text-sm font-semibold text-white">
                Incident Investigation Reports ({report.incidents_summary.length})
              </h3>
              <p className="text-[11px] text-slate-400">
                Export standalone CSV or PDF Incident Investigation Reports containing correlated alerts, MITRE ATT&CK mappings, forensic evidence, timeline, and analyst notes
              </p>
            </div>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="bg-[#0c121e] border-b border-[#1e2c45] text-slate-400 text-[11px] uppercase">
                  <th className="py-2.5 px-3">Incident ID</th>
                  <th className="py-2.5 px-3">Title</th>
                  <th className="py-2.5 px-3">Severity</th>
                  <th className="py-2.5 px-3">Status</th>
                  <th className="py-2.5 px-3">Assigned Analyst</th>
                  <th className="py-2.5 px-3">Alerts / Evidence</th>
                  <th className="py-2.5 px-3">Export Incident Report</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1e2c45]">
                {report.incidents_summary.map((inc: any) => (
                  <tr key={inc.id} className="hover:bg-[#151f32]">
                    <td className="py-2.5 px-3 font-mono font-semibold text-orange-400">
                      {inc.incident_id}
                    </td>
                    <td className="py-2.5 px-3 font-medium text-white">{inc.title}</td>
                    <td className="py-2.5 px-3">
                      <SeverityBadge severity={inc.severity} />
                    </td>
                    <td className="py-2.5 px-3">
                      <IncidentStatusBadge status={inc.status} />
                    </td>
                    <td className="py-2.5 px-3 font-mono text-slate-300">
                      {inc.assigned_analyst || 'Unassigned'}
                    </td>
                    <td className="py-2.5 px-3 font-mono text-slate-300">
                      {inc.linked_alert_count} alerts • {inc.evidence_count} evidence refs
                    </td>
                    <td className="py-2.5 px-3">
                      <div className="flex items-center gap-2">
                        <a
                          href={api.getIncidentCsvReportUrl(inc.incident_id)}
                          download
                          className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-[#151f32] hover:bg-[#1e2c45] border border-cyan-500/40 text-cyan-300 text-[11px]"
                        >
                          <FileSpreadsheet className="w-3 h-3" />
                          Incident CSV
                        </a>
                        <a
                          href={api.getIncidentPdfReportUrl(inc.incident_id)}
                          download
                          className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-cyan-600 hover:bg-cyan-500 text-white text-[11px]"
                        >
                          <FileText className="w-3 h-3" />
                          Incident PDF
                        </a>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Per-Rule Performance Matrix Table */}
      <div className="soc-panel overflow-hidden">
        <div className="p-4 border-b border-[#1e2c45] flex items-center justify-between">
          <div>
            <h3 className="text-sm font-semibold text-white">
              Detection Rule Performance & MITRE ATT&CK Matrix
            </h3>
            <p className="text-[11px] text-slate-400">
              Granular per-rule alert counts, True Positives, False Positives, False Negatives, Precision, Recall, and F1 Score
            </p>
          </div>
          <a
            href={api.getCsvReportUrl()}
            download
            className="inline-flex items-center gap-1 text-xs text-cyan-400 hover:underline"
          >
            <Download className="w-3.5 h-3.5" />
            Download Full Table (CSV)
          </a>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="bg-[#0c121e] border-b border-[#1e2c45] text-slate-400 text-[11px] uppercase">
                <th className="py-2.5 px-3">Rule ID</th>
                <th className="py-2.5 px-3">Rule Name</th>
                <th className="py-2.5 px-3">MITRE Technique</th>
                <th className="py-2.5 px-3">Severity</th>
                <th className="py-2.5 px-3">Alerts</th>
                <th className="py-2.5 px-3">TP</th>
                <th className="py-2.5 px-3">FP</th>
                <th className="py-2.5 px-3">FN</th>
                <th className="py-2.5 px-3">Precision</th>
                <th className="py-2.5 px-3">Recall</th>
                <th className="py-2.5 px-3">F1 Score</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1e2c45]">
              {report.rule_performance.map((r: any) => (
                <tr key={r.rule_id} className="hover:bg-[#151f32]">
                  <td className="py-2.5 px-3 font-mono font-semibold text-cyan-400">
                    {r.rule_id}
                  </td>
                  <td className="py-2.5 px-3 font-medium text-white">{r.name}</td>
                  <td className="py-2.5 px-3 font-mono text-slate-300">
                    {r.mitre_technique_id} ({r.mitre_tactic})
                  </td>
                  <td className="py-2.5 px-3">
                    <SeverityBadge severity={r.severity} />
                  </td>
                  <td className="py-2.5 px-3 font-mono text-white font-semibold">
                    {r.alerts_generated}
                  </td>
                  <td className="py-2.5 px-3 font-mono text-emerald-400">
                    {r.true_positives}
                  </td>
                  <td className="py-2.5 px-3 font-mono text-red-400">
                    {r.false_positives}
                  </td>
                  <td className="py-2.5 px-3 font-mono text-orange-400">
                    {r.false_negatives}
                  </td>
                  <td className="py-2.5 px-3 font-mono text-slate-200">
                    {r.precision !== null ? `${(r.precision * 100).toFixed(1)}%` : '—'}
                  </td>
                  <td className="py-2.5 px-3 font-mono text-slate-200">
                    {r.recall !== null ? `${(r.recall * 100).toFixed(1)}%` : '—'}
                  </td>
                  <td className="py-2.5 px-3 font-mono text-cyan-300 font-semibold">
                    {r.f1_score !== null ? `${(r.f1_score * 100).toFixed(1)}%` : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

