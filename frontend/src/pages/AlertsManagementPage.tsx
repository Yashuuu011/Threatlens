import React, { useCallback, useEffect, useState } from 'react';
import { useNavigate, useParams, useSearchParams } from 'react-router-dom';
import {
  ArrowUpDown,
  ChevronLeft,
  ChevronRight,
  Clock,
  FileSpreadsheet,
  FolderPlus,
  Globe,
  Maximize2,
  MessageSquarePlus,
  Minimize2,
  RefreshCw,
  Search,
  ShieldAlert,
} from 'lucide-react';
import { api } from '../services/api';
import { AlertDetail, AlertItem, AlertStatus } from '../types';
import { AlertStatusBadge, SeverityBadge } from '../components/SeverityBadge';
import { formatTimestamp } from '../utils/formatters';
import { ThreatIntelModal } from '../components/ThreatIntelModal';

const ALERT_STATUSES: AlertStatus[] = [
  'New',
  'Acknowledged',
  'Investigating',
  'Resolved',
  'False Positive',
];

export const AlertsManagementPage: React.FC = () => {
  const navigate = useNavigate();
  const { alertId: routeAlertId } = useParams<{ alertId?: string }>();
  const [searchParams, setSearchParams] = useSearchParams();

  // Filters & Sorting
  const [search, setSearch] = useState(searchParams.get('search') || '');
  const [severity, setSeverity] = useState(searchParams.get('severity') || 'all');
  const [statusFilter, setStatusFilter] = useState(searchParams.get('status') || 'all');
  const [ruleCode, setRuleCode] = useState(searchParams.get('rule_code') || 'all');
  const [sortBy, setSortBy] = useState<string>('last_seen');
  const [sortOrder, setSortOrder] = useState<'desc' | 'asc'>('desc');
  const [page, setPage] = useState(1);
  const [pageSize] = useState(15);
  const [fullPageDetail, setFullPageDetail] = useState<boolean>(Boolean(routeAlertId));

  // List & Detail State
  const [alerts, setAlerts] = useState<AlertItem[]>([]);
  const [total, setTotal] = useState(0);
  const [totalPages, setTotalPages] = useState(1);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [selectedAlert, setSelectedAlert] = useState<AlertDetail | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);

  // Status update & note forms
  const [newStatus, setNewStatus] = useState<AlertStatus>('Investigating');
  const [statusComment, setStatusComment] = useState('');
  const [assignedTo, setAssignedTo] = useState('');
  const [noteInput, setNoteInput] = useState('');
  const [actionFeedback, setActionFeedback] = useState<string | null>(null);

  // Contextual Threat Intelligence Enrichment State
  const [threatIntelOpen, setThreatIntelOpen] = useState(false);
  const [threatIntelIp, setThreatIntelIp] = useState<string>('');

  const handleOpenThreatIntel = (ip: string) => {
    setThreatIntelIp(ip);
    setThreatIntelOpen(true);
  };

  const handleAttachIntelToAlert = async (intelNote: string) => {
    if (!selectedAlert) return;
    try {
      await api.addAlertNote(selectedAlert.id, intelNote);
      setActionFeedback(`Threat intelligence attached to alert #${selectedAlert.id}`);
      await loadAlertDetail(selectedAlert.id);
    } catch (err: any) {
      setActionFeedback(`Failed to attach note: ${err.message}`);
    }
  };

  const fetchAlerts = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.listAlerts({
        search: search.trim() || undefined,
        severity,
        status: statusFilter,
        rule_code: ruleCode,
        sort_by: sortBy,
        sort_order: sortOrder,
        page,
        page_size: pageSize,
      });
      setAlerts(res.items);
      setTotal(res.total);
      setTotalPages(res.total_pages);

      const targetAlertId = routeAlertId || searchParams.get('alertId');
      if (targetAlertId) {
        loadAlertDetail(targetAlertId);
      } else if (!selectedAlert && res.items.length > 0) {
        loadAlertDetail(res.items[0].id);
      }
    } catch (err: any) {
      setError(err.message || 'Failed to load alerts from PostgreSQL');
    } finally {
      setLoading(false);
    }
  }, [search, severity, statusFilter, ruleCode, sortBy, sortOrder, page, pageSize, routeAlertId]);

  const loadAlertDetail = async (id: string | number) => {
    setDetailLoading(true);
    try {
      const det = await api.getAlertDetail(id);
      setSelectedAlert(det);
      setNewStatus(det.status);
      setAssignedTo(det.assigned_to || 'analyst');
    } finally {
      setDetailLoading(false);
    }
  };

  useEffect(() => {
    fetchAlerts();
  }, [fetchAlerts]);

  const handleUpdateStatus = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedAlert) return;
    setActionFeedback(null);
    try {
      const updated = await api.updateAlertStatus(
        selectedAlert.id,
        newStatus,
        statusComment.trim() || undefined,
        assignedTo.trim() || undefined
      );
      setSelectedAlert(updated);
      setStatusComment('');
      setActionFeedback(`Alert ${updated.alert_id} status updated to '${updated.status}'.`);
      fetchAlerts();
    } catch (err: any) {
      setActionFeedback(`Error: ${err.message}`);
    }
  };

  const handleAddNote = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedAlert || !noteInput.trim()) return;
    try {
      await api.addAlertNote(selectedAlert.id, noteInput.trim());
      setNoteInput('');
      await loadAlertDetail(selectedAlert.id);
      setActionFeedback('Investigation note added.');
    } catch (err: any) {
      setActionFeedback(`Error: ${err.message}`);
    }
  };

  const handleEscalateToIncident = async () => {
    if (!selectedAlert) return;
    try {
      const created = await api.createIncident({
        title: `Escalated Investigation: ${selectedAlert.title}`,
        severity: selectedAlert.severity,
        description: `Incident created from alert ${selectedAlert.alert_id} (${selectedAlert.rule_code} - ${selectedAlert.rule_name}). ${selectedAlert.description}`,
        assigned_analyst: assignedTo || 'analyst',
        alert_ids: [selectedAlert.id],
      });
      navigate(`/incidents?incidentId=${created.id}`);
    } catch (err: any) {
      setActionFeedback(`Escalation failed: ${err.message}`);
    }
  };

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-white">Alerts Management & SOC Triage</h1>
          <p className="text-xs text-slate-400">
            Search, filter, sort, investigate, transition alert lifecycles, and escalate correlated alerts into incidents
          </p>
        </div>
        <button
          onClick={fetchAlerts}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-[#0f1623] hover:bg-[#151f32] border border-[#1e2c45] text-slate-200 text-xs self-start"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          Refresh Alerts
        </button>
      </div>

      {/* Filter & Sort Controls */}
      <div className="soc-panel p-4 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-6 gap-3 text-xs">
        <div className="lg:col-span-2">
          <label className="block text-[11px] text-slate-400 mb-1">
            Search Alerts (ID, Title, Source IP, Username, MITRE)
          </label>
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-2.5" />
            <input
              type="text"
              value={search}
              onChange={(e) => {
                setSearch(e.target.value);
                setPage(1);
              }}
              placeholder="Search alert title, IP, username, T1110..."
              className="w-full bg-[#090d16] border border-[#1e2c45] rounded pl-8 pr-2.5 py-1.5 text-slate-100"
            />
          </div>
        </div>

        <div>
          <label className="block text-[11px] text-slate-400 mb-1">Severity</label>
          <select
            value={severity}
            onChange={(e) => {
              setSeverity(e.target.value);
              setPage(1);
            }}
            className="w-full bg-[#090d16] border border-[#1e2c45] rounded px-2.5 py-1.5 text-slate-100"
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>

        <div>
          <label className="block text-[11px] text-slate-400 mb-1">Alert Status</label>
          <select
            value={statusFilter}
            onChange={(e) => {
              setStatusFilter(e.target.value);
              setPage(1);
            }}
            className="w-full bg-[#090d16] border border-[#1e2c45] rounded px-2.5 py-1.5 text-slate-100"
          >
            <option value="all">All Statuses</option>
            {ALERT_STATUSES.map((st) => (
              <option key={st} value={st}>
                {st}
              </option>
            ))}
          </select>
        </div>

        <div>
          <label className="block text-[11px] text-slate-400 mb-1">Sort Field</label>
          <select
            value={sortBy}
            onChange={(e) => {
              setSortBy(e.target.value);
              setPage(1);
            }}
            className="w-full bg-[#090d16] border border-[#1e2c45] rounded px-2.5 py-1.5 text-slate-100"
          >
            <option value="last_seen">Last Seen Time</option>
            <option value="severity">Severity</option>
            <option value="status">Alert Status</option>
            <option value="event_count">Event Count</option>
            <option value="rule_code">Rule Code</option>
            <option value="source_ip">Source IP</option>
          </select>
        </div>

        <div>
          <label className="block text-[11px] text-slate-400 mb-1">Sort Direction</label>
          <button
            onClick={() => setSortOrder((prev) => (prev === 'desc' ? 'asc' : 'desc'))}
            className="w-full bg-[#090d16] border border-[#1e2c45] hover:border-cyan-500/40 rounded px-2.5 py-1.5 text-slate-200 flex items-center justify-between"
          >
            <span>{sortOrder === 'desc' ? 'Descending' : 'Ascending'}</span>
            <ArrowUpDown className="w-3.5 h-3.5 text-cyan-400" />
          </button>
        </div>
      </div>

      {error && (
        <div className="soc-panel p-4 border-red-500/40 bg-red-950/20 text-red-200 text-xs flex items-center justify-between">
          <span>{error}</span>
          <button
            onClick={fetchAlerts}
            className="px-3 py-1 rounded bg-red-600 hover:bg-red-500 text-white font-medium"
          >
            Retry
          </button>
        </div>
      )}

      {/* Split Workspace: Alerts Table (Left) + Alert Investigation Panel (Right) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* Left Column: Alerts Table */}
        {!fullPageDetail && (
          <div className="lg:col-span-5 soc-panel flex flex-col justify-between overflow-hidden">
          <div>
            <div className="px-4 py-3 border-b border-[#1e2c45] flex items-center justify-between text-xs">
              <span className="font-semibold text-white">
                Alerts Queue ({total})
              </span>
              {ruleCode !== 'all' && (
                <button
                  onClick={() => {
                    setRuleCode('all');
                    setSearchParams({});
                  }}
                  className="text-cyan-400 hover:underline text-[11px]"
                >
                  Clear Rule Filter ({ruleCode})
                </button>
              )}
            </div>

            <div className="divide-y divide-[#1e2c45] max-h-[680px] overflow-y-auto">
              {loading ? (
                <div className="p-8 text-center text-xs text-slate-400">
                  Loading alerts from PostgreSQL...
                </div>
              ) : alerts.length === 0 ? (
                <div className="p-8 text-center text-xs text-slate-400">
                  No alerts match the current filter criteria.
                </div>
              ) : (
                alerts.map((al) => {
                  const isSelected = selectedAlert?.id === al.id;
                  return (
                    <div
                      key={al.id}
                      onClick={() => loadAlertDetail(al.id)}
                      className={`p-3.5 cursor-pointer transition-colors space-y-1.5 text-xs ${
                        isSelected
                          ? 'bg-[#151f32] border-l-2 border-l-cyan-400'
                          : 'hover:bg-[#121b2c]'
                      }`}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-mono text-cyan-400 font-semibold">
                          {al.alert_id}
                        </span>
                        <div className="flex items-center gap-1.5">
                          <SeverityBadge severity={al.severity} />
                          <AlertStatusBadge status={al.status} />
                        </div>
                      </div>
                      <div className="font-medium text-slate-100 leading-snug">
                        {al.title}
                      </div>
                      <div className="flex items-center justify-between text-[11px] text-slate-400 font-mono">
                        <span>
                          {al.rule_code} ({al.mitre_technique_id || 'SIEM'})
                        </span>
                        <span>{al.event_count} event(s)</span>
                      </div>
                      <div className="flex items-center justify-between text-[11px] text-slate-400">
                        <span>IP: {al.source_ip || '—'}</span>
                        <span>{formatTimestamp(al.last_seen)}</span>
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </div>

          {/* Pagination */}
          <div className="px-4 py-2.5 border-t border-[#1e2c45] flex items-center justify-between text-xs">
            <span className="text-slate-400">
              Page {page} / {totalPages}
            </span>
            <div className="flex items-center gap-1.5">
              <button
                disabled={page <= 1}
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                className="p-1 rounded bg-[#090d16] border border-[#1e2c45] disabled:opacity-40"
              >
                <ChevronLeft className="w-3.5 h-3.5" />
              </button>
              <button
                disabled={page >= totalPages}
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                className="p-1 rounded bg-[#090d16] border border-[#1e2c45] disabled:opacity-40"
              >
                <ChevronRight className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        </div>
        )}

        {/* Right Column: Alert Investigation & Evidence Workspace */}
        <div className={`${fullPageDetail ? 'lg:col-span-12' : 'lg:col-span-7'} soc-panel p-5 space-y-5 text-xs`}>
          {detailLoading ? (
            <div className="py-16 text-center text-slate-400">
              Loading alert forensic context, evidence events, and status history...
            </div>
          ) : !selectedAlert ? (
            <div className="py-16 text-center text-slate-400">
              Select an alert from the queue to inspect evidence and manage triage status.
            </div>
          ) : (
            <>
              {/* Alert Header */}
              <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-3 border-b border-[#1e2c45] pb-4">
                <div className="space-y-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-cyan-400 font-bold text-sm">
                      {selectedAlert.alert_id}
                    </span>
                    <SeverityBadge severity={selectedAlert.severity} />
                    <AlertStatusBadge status={selectedAlert.status} />
                    {selectedAlert.mitre_technique_id && (
                      <span className="px-2 py-0.5 rounded bg-blue-500/15 text-blue-300 border border-blue-500/30 font-mono text-[11px]">
                        MITRE {selectedAlert.mitre_tactic ? `${selectedAlert.mitre_tactic} • ` : ''}
                        {selectedAlert.mitre_technique_id}:{' '}
                        {selectedAlert.mitre_technique_name}
                      </span>
                    )}
                    {selectedAlert.linked_incident_ids &&
                      selectedAlert.linked_incident_ids.map((incCode) => (
                        <button
                          key={incCode}
                          type="button"
                          onClick={() => navigate(`/incidents?incidentId=${encodeURIComponent(incCode)}`)}
                          className="px-2 py-0.5 rounded bg-orange-500/15 text-orange-300 border border-orange-500/30 font-mono text-[11px] hover:underline"
                        >
                          Incident: {incCode}
                        </button>
                      ))}
                  </div>
                  <h2 className="text-base font-bold text-white pt-1">
                    {selectedAlert.title}
                  </h2>
                  <p className="text-slate-300 leading-relaxed">
                    {selectedAlert.description}
                  </p>
                </div>

                <div className="flex items-center gap-2 shrink-0">
                  <button
                    onClick={() => setFullPageDetail((prev) => !prev)}
                    className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded bg-[#151f32] hover:bg-[#1e2c45] border border-[#243554] text-slate-200 font-medium"
                    title={fullPageDetail ? 'Show Split Queue View' : 'Expand Full Alert Details Page'}
                  >
                    {fullPageDetail ? (
                      <>
                        <Minimize2 className="w-3.5 h-3.5 text-cyan-400" />
                        Split Queue
                      </>
                    ) : (
                      <>
                        <Maximize2 className="w-3.5 h-3.5 text-cyan-400" />
                        Full Details
                      </>
                    )}
                  </button>
                  {selectedAlert.source_ip && (
                    <button
                      type="button"
                      onClick={() => handleOpenThreatIntel(selectedAlert.source_ip!)}
                      className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded bg-[#151f32] hover:bg-[#1e2c45] border border-cyan-500/40 text-cyan-300 font-medium shrink-0"
                      title="Enrich alert with Threat Intelligence"
                    >
                      <Globe className="w-3.5 h-3.5 text-cyan-400" />
                      Threat Intel
                    </button>
                  )}
                  <button
                    onClick={handleEscalateToIncident}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-orange-600 hover:bg-orange-500 text-white font-medium shrink-0"
                  >
                    <FolderPlus className="w-3.5 h-3.5" />
                    Create Incident from Alert
                  </button>
                </div>
              </div>

              {actionFeedback && (
                <div className="p-2.5 rounded bg-cyan-500/15 border border-cyan-500/40 text-cyan-200">
                  {actionFeedback}
                </div>
              )}

              {/* Metadata Grid */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 bg-[#151f32] border border-[#243554] rounded p-3">
                <div>
                  <div className="text-[10px] uppercase text-slate-400">Detection Rule</div>
                  <div className="font-mono text-cyan-300 font-semibold mt-0.5">
                    {selectedAlert.rule_code}
                  </div>
                  <div className="text-[11px] text-slate-300 truncate">
                    {selectedAlert.rule_name}
                  </div>
                </div>
                <div>
                  <div className="text-[10px] uppercase text-slate-400">Source IP</div>
                  <div className="font-mono text-white mt-0.5">
                    {selectedAlert.source_ip || '—'}
                  </div>
                  {selectedAlert.source_ip && (
                    <button
                      type="button"
                      onClick={() => handleOpenThreatIntel(selectedAlert.source_ip!)}
                      className="text-[10px] text-cyan-400 hover:underline flex items-center gap-1 mt-0.5"
                    >
                      <Globe className="w-3 h-3 text-cyan-400" />
                      Enrich Threat Intel →
                    </button>
                  )}
                </div>
                <div>
                  <div className="text-[10px] uppercase text-slate-400">Associated User</div>
                  <div className="text-white font-medium mt-0.5">
                    {selectedAlert.username || '—'}
                  </div>
                  <div className="text-[11px] text-slate-400 font-mono">
                    Host: {selectedAlert.hostname || '—'}
                  </div>
                </div>
                <div>
                  <div className="text-[10px] uppercase text-slate-400">
                    Detection Window ({selectedAlert.event_count} events)
                  </div>
                  <div className="font-mono text-[11px] text-slate-200 mt-0.5">
                    First: {formatTimestamp(selectedAlert.first_seen)}
                  </div>
                  <div className="font-mono text-[11px] text-slate-200">
                    Last: {formatTimestamp(selectedAlert.last_seen)}
                  </div>
                </div>
              </div>

              {/* Status Update Workflow Form */}
              <form
                onSubmit={handleUpdateStatus}
                className="p-3.5 rounded bg-[#090d16] border border-[#1e2c45] space-y-3"
              >
                <div className="font-semibold text-white flex items-center gap-1.5">
                  <ShieldAlert className="w-4 h-4 text-cyan-400" />
                  <span>Update Alert Triage Status</span>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                  <div>
                    <label className="block text-[11px] text-slate-400 mb-1">New Status</label>
                    <select
                      value={newStatus}
                      onChange={(e) => setNewStatus(e.target.value as AlertStatus)}
                      className="w-full bg-[#0f1623] border border-[#1e2c45] rounded px-2.5 py-1.5 text-white"
                    >
                      {ALERT_STATUSES.map((st) => (
                        <option key={st} value={st}>
                          {st}
                        </option>
                      ))}
                    </select>
                  </div>
                  <div>
                    <label className="block text-[11px] text-slate-400 mb-1">
                      Assigned Analyst
                    </label>
                    <input
                      type="text"
                      value={assignedTo}
                      onChange={(e) => setAssignedTo(e.target.value)}
                      placeholder="analyst"
                      className="w-full bg-[#0f1623] border border-[#1e2c45] rounded px-2.5 py-1.5 text-white"
                    />
                  </div>
                  <div>
                    <label className="block text-[11px] text-slate-400 mb-1">
                      Status Transition Note
                    </label>
                    <input
                      type="text"
                      value={statusComment}
                      onChange={(e) => setStatusComment(e.target.value)}
                      placeholder="Reason for status change..."
                      className="w-full bg-[#0f1623] border border-[#1e2c45] rounded px-2.5 py-1.5 text-white"
                    />
                  </div>
                </div>
                <div className="flex justify-end">
                  <button
                    type="submit"
                    className="px-3.5 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-white font-medium"
                  >
                    Save Status Update
                  </button>
                </div>
              </form>

              {/* Associated Security Events (Evidence References) */}
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-white flex items-center gap-1.5">
                    <FileSpreadsheet className="w-4 h-4 text-cyan-400" />
                    Associated Triggering Security Events ({selectedAlert.evidence_events.length})
                  </span>
                  <span className="text-[11px] font-mono text-slate-400">
                    Evidence Traceability
                  </span>
                </div>
                <div className="border border-[#1e2c45] rounded overflow-hidden max-h-56 overflow-y-auto">
                  <table className="w-full text-left border-collapse text-[11px]">
                    <thead>
                      <tr className="bg-[#0c121e] border-b border-[#1e2c45] text-slate-400 uppercase">
                        <th className="py-2 px-2.5">Event ID</th>
                        <th className="py-2 px-2.5">Timestamp</th>
                        <th className="py-2 px-2.5">Type / Action</th>
                        <th className="py-2 px-2.5">Source IP</th>
                        <th className="py-2 px-2.5">User</th>
                        <th className="py-2 px-2.5">Status</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#1e2c45]">
                      {selectedAlert.evidence_events.map((ev) => (
                        <tr
                          key={ev.id}
                          onClick={() =>
                            navigate(`/events?search=${encodeURIComponent(ev.event_id)}`)
                          }
                          className="hover:bg-[#151f32] cursor-pointer"
                        >
                          <td className="py-2 px-2.5 font-mono text-cyan-400">{ev.event_id}</td>
                          <td className="py-2 px-2.5 font-mono text-slate-300">
                            {formatTimestamp(ev.timestamp)}
                          </td>
                          <td className="py-2 px-2.5 text-slate-200">
                            {ev.event_type} ({ev.action})
                          </td>
                          <td className="py-2 px-2.5 font-mono text-slate-300">{ev.source_ip}</td>
                          <td className="py-2 px-2.5 text-slate-300">{ev.username || '—'}</td>
                          <td className="py-2 px-2.5 font-mono text-slate-300">{ev.status}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Analyst Investigation Notes & Status History */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {/* Analyst Notes */}
                <div className="space-y-2">
                  <div className="font-semibold text-white flex items-center gap-1.5">
                    <MessageSquarePlus className="w-4 h-4 text-cyan-400" />
                    <span>Analyst Investigation Notes ({selectedAlert.notes.length})</span>
                  </div>
                  <form onSubmit={handleAddNote} className="flex gap-2">
                    <input
                      type="text"
                      value={noteInput}
                      onChange={(e) => setNoteInput(e.target.value)}
                      placeholder="Add forensic observation..."
                      className="flex-1 bg-[#090d16] border border-[#1e2c45] rounded px-2.5 py-1.5 text-white"
                    />
                    <button
                      type="submit"
                      className="px-3 py-1.5 rounded bg-[#151f32] hover:bg-cyan-600 border border-cyan-500/40 text-white font-medium"
                    >
                      Add
                    </button>
                  </form>
                  <div className="space-y-2 max-h-48 overflow-y-auto">
                    {selectedAlert.notes.length === 0 ? (
                      <div className="text-slate-500 italic">No analyst notes recorded yet.</div>
                    ) : (
                      selectedAlert.notes.map((n) => (
                        <div
                          key={n.id}
                          className="p-2.5 rounded bg-[#090d16] border border-[#1e2c45] space-y-1"
                        >
                          <div className="flex items-center justify-between text-[10px] text-slate-400">
                            <span className="font-semibold text-cyan-400">{n.author}</span>
                            <span className="font-mono">{formatTimestamp(n.created_at)}</span>
                          </div>
                          <p className="text-slate-200">{n.content}</p>
                        </div>
                      ))
                    )}
                  </div>
                </div>

                {/* Status Change History */}
                <div className="space-y-2">
                  <div className="font-semibold text-white flex items-center gap-1.5">
                    <Clock className="w-4 h-4 text-blue-400" />
                    <span>Alert Status Audit History ({selectedAlert.status_history.length})</span>
                  </div>
                  <div className="space-y-2 max-h-60 overflow-y-auto">
                    {selectedAlert.status_history.map((h) => (
                      <div
                        key={h.id}
                        className="p-2.5 rounded bg-[#090d16] border border-[#1e2c45] space-y-1"
                      >
                        <div className="flex items-center justify-between text-[11px]">
                          <span className="font-semibold text-white">
                            {h.previous_status ? `${h.previous_status} → ` : ''}
                            <span className="text-cyan-400">{h.new_status}</span>
                          </span>
                          <span className="font-mono text-[10px] text-slate-400">
                            {formatTimestamp(h.created_at)}
                          </span>
                        </div>
                        <div className="text-[11px] text-slate-400">
                          By <span className="text-slate-200">{h.changed_by}</span>:{' '}
                          {h.comment || 'Status updated'}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </>
          )}
        </div>
      </div>

      {/* On-Demand Threat Intelligence Enrichment Modal */}
      <ThreatIntelModal
        isOpen={threatIntelOpen}
        onClose={() => setThreatIntelOpen(false)}
        initialIp={threatIntelIp}
        onAttachEvidenceNote={handleAttachIntelToAlert}
      />
    </div>
  );
};

