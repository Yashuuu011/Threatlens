import React, { useCallback, useEffect, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import {
  CheckCircle2,
  Clock,
  ExternalLink,
  FileCheck2,
  FolderPlus,
  Globe,
  Link2,
  MessageSquare,
  Plus,
  RefreshCw,
  Search,
  ShieldAlert,
  Trash2,
  UserCheck,
  X,
} from 'lucide-react';
import { api } from '../services/api';
import {
  AlertItem,
  IncidentDetail,
  IncidentItem,
  IncidentStatus,
  MitreMappingItem,
} from '../types';
import {
  AlertStatusBadge,
  IncidentStatusBadge,
  SeverityBadge,
} from '../components/SeverityBadge';
import { formatTimestamp } from '../utils/formatters';
import { ThreatIntelModal } from '../components/ThreatIntelModal';

const INCIDENT_STATUSES: IncidentStatus[] = [
  'Open',
  'Investigating',
  'Contained',
  'Resolved',
  'Closed',
];

export const IncidentInvestigationPage: React.FC = () => {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();

  // Filter state
  const [search, setSearch] = useState(searchParams.get('search') || '');
  const [statusFilter, setStatusFilter] = useState(searchParams.get('status') || 'all');
  const [severityFilter, setSeverityFilter] = useState(searchParams.get('severity') || 'all');
  const [analystFilter, setAnalystFilter] = useState(searchParams.get('assigned_analyst') || 'all');

  const [incidents, setIncidents] = useState<IncidentItem[]>([]);
  const [selectedIncident, setSelectedIncident] = useState<IncidentDetail | null>(null);
  const [availableAlerts, setAvailableAlerts] = useState<AlertItem[]>([]);
  const [platformMitre, setPlatformMitre] = useState<MitreMappingItem[]>([]);
  const [showAllMitreRules, setShowAllMitreRules] = useState(false);
  const [loading, setLoading] = useState(true);

  // Update Incident State
  const [editStatus, setEditStatus] = useState<IncidentStatus>('Investigating');
  const [editAssignee, setEditAssignee] = useState('');
  const [editStatusComment, setEditStatusComment] = useState('');
  const [editResolution, setEditResolution] = useState('');

  // Note state
  const [noteText, setNoteText] = useState('');
  const [noteType, setNoteType] = useState('investigation_note');

  // Alert link state
  const [alertIdToLink, setAlertIdToLink] = useState<string>('');

  // Evidence reference form state
  const [evidenceType, setEvidenceType] = useState<string>('artifact');
  const [evidenceRef, setEvidenceRef] = useState<string>('');
  const [evidenceDesc, setEvidenceDesc] = useState<string>('');

  const [feedback, setFeedback] = useState<string | null>(null);

  // Threat Intelligence Enrichment State
  const [threatIntelOpen, setThreatIntelOpen] = useState(false);
  const [threatIntelIp, setThreatIntelIp] = useState<string>('');

  const handleOpenThreatIntel = (ip?: string) => {
    const defaultIp =
      ip ||
      selectedIncident?.related_alerts?.find((a) => a.source_ip)?.source_ip ||
      '185.220.101.42';
    setThreatIntelIp(defaultIp);
    setThreatIntelOpen(true);
  };

  const handleAttachIntelToIncident = async (intelNote: string) => {
    if (!selectedIncident) return;
    try {
      await api.addIncidentNote(selectedIncident.incident_id, intelNote, 'evidence_note');
      setFeedback('Attached threat intelligence verdict to incident notes.');
      await selectIncident(selectedIncident.incident_id);
    } catch (err: any) {
      setFeedback(`Failed to attach threat intel note: ${err.message}`);
    }
  };

  // Create Incident Modal
  const [createModalOpen, setCreateModalOpen] = useState(false);
  const [newIncTitle, setNewIncTitle] = useState('');
  const [newIncSeverity, setNewIncSeverity] = useState('high');
  const [newIncStatus, setNewIncStatus] = useState<IncidentStatus>('Open');
  const [newIncDesc, setNewIncDesc] = useState('');
  const [newIncAssignee, setNewIncAssignee] = useState('analyst');
  const [selectedAlertIds, setSelectedAlertIds] = useState<number[]>([]);

  const selectIncident = useCallback(async (id: string | number) => {
    const det = await api.getIncidentDetail(id);
    setSelectedIncident(det);
    setEditStatus(det.status);
    setEditAssignee(det.assigned_analyst || 'analyst');
    setEditResolution(det.resolution_summary || '');
    setEditStatusComment('');
  }, []);

  const loadIncidents = useCallback(async () => {
    setLoading(true);
    try {
      const [incRes, alertsRes, mitreRes] = await Promise.all([
        api.listIncidents({
          search: search.trim() || undefined,
          status: statusFilter,
          severity: severityFilter,
          assigned_analyst: analystFilter,
          page: 1,
          page_size: 50,
        }),
        api.listAlerts({ page: 1, page_size: 50 }),
        api.getMitreMappings().catch(() => ({ mappings: [] })),
      ]);
      setIncidents(incRes.items);
      setAvailableAlerts(alertsRes.items);
      setPlatformMitre(mitreRes?.mappings || []);

      const paramId = searchParams.get('incidentId');
      if (paramId) {
        await selectIncident(paramId);
      } else if (incRes.items.length > 0) {
        const currentStillInList =
          selectedIncident && incRes.items.some((i) => i.id === selectedIncident.id);
        if (currentStillInList) {
          await selectIncident(selectedIncident!.id);
        } else {
          await selectIncident(incRes.items[0].id);
        }
      } else {
        setSelectedIncident(null);
      }
    } finally {
      setLoading(false);
    }
  }, [search, statusFilter, severityFilter, analystFilter, searchParams, selectIncident]);

  useEffect(() => {
    loadIncidents();
  }, [loadIncidents]);

  const handleSaveIncidentUpdate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedIncident) return;
    setFeedback(null);
    try {
      const updated = await api.updateIncident(selectedIncident.id, {
        status: editStatus,
        assigned_analyst: editAssignee,
        resolution_summary: editResolution,
        comment: editStatusComment.trim() || undefined,
      });
      setSelectedIncident(updated);
      setEditStatusComment('');
      setFeedback(
        `Incident ${updated.incident_id} updated (Status: ${updated.status}, Analyst: ${
          updated.assigned_analyst || 'Unassigned'
        }).`
      );
      loadIncidents();
    } catch (err: any) {
      setFeedback(`Error: ${err.message}`);
    }
  };

  const handleQuickStatusChange = async (targetStatus: IncidentStatus) => {
    if (!selectedIncident || selectedIncident.status === targetStatus) return;
    setFeedback(null);
    try {
      const updated = await api.updateIncidentStatus(selectedIncident.id, {
        status: targetStatus,
        assigned_analyst: editAssignee || selectedIncident.assigned_analyst || 'analyst',
        comment:
          editStatusComment.trim() ||
          `Transitioned incident status from ${selectedIncident.status} to ${targetStatus}`,
      });
      setSelectedIncident(updated);
      setEditStatus(updated.status);
      setEditStatusComment('');
      setFeedback(`Incident ${updated.incident_id} status transitioned to '${updated.status}'.`);
      loadIncidents();
    } catch (err: any) {
      setFeedback(`Error: ${err.message}`);
    }
  };

  const handleAddIncidentNote = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedIncident || !noteText.trim()) return;
    try {
      await api.addIncidentNote(selectedIncident.id, noteText.trim(), noteType);
      setNoteText('');
      await selectIncident(selectedIncident.id);
      setFeedback('Added investigation note to incident timeline.');
    } catch (err: any) {
      setFeedback(`Error: ${err.message}`);
    }
  };

  const handleLinkAlert = async () => {
    if (!selectedIncident || !alertIdToLink) return;
    try {
      const updated = await api.linkAlertsToIncident(selectedIncident.id, [
        Number(alertIdToLink),
      ]);
      setSelectedIncident(updated);
      setAlertIdToLink('');
      setFeedback('Linked alert and correlated security events to incident.');
      loadIncidents();
    } catch (err: any) {
      setFeedback(`Error: ${err.message}`);
    }
  };

  const handleUnlinkAlert = async (alertId: number, alertCode: string) => {
    if (!selectedIncident) return;
    try {
      const updated = await api.unlinkAlertFromIncident(selectedIncident.id, alertId);
      setSelectedIncident(updated);
      setFeedback(`Unlinked alert ${alertCode} from incident.`);
      loadIncidents();
    } catch (err: any) {
      setFeedback(`Error: ${err.message}`);
    }
  };

  const handleAddEvidence = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedIncident || !evidenceRef.trim()) return;
    try {
      const updated = await api.addIncidentEvidence(selectedIncident.id, {
        type: evidenceType,
        reference: evidenceRef.trim(),
        description: evidenceDesc.trim() || undefined,
      });
      setSelectedIncident(updated);
      setEvidenceRef('');
      setEvidenceDesc('');
      setFeedback('Added forensic evidence reference to incident.');
    } catch (err: any) {
      setFeedback(`Error: ${err.message}`);
    }
  };

  const handleCreateIncident = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const created = await api.createIncident({
        title: newIncTitle,
        severity: newIncSeverity,
        status: newIncStatus,
        description: newIncDesc,
        assigned_analyst: newIncAssignee,
        alert_ids: selectedAlertIds,
      });
      setCreateModalOpen(false);
      setNewIncTitle('');
      setNewIncDesc('');
      setSelectedAlertIds([]);
      await loadIncidents();
      await selectIncident(created.id);
      setFeedback(`Created incident ${created.incident_id} (${created.status}).`);
    } catch (err: any) {
      setFeedback(`Error: ${err.message}`);
    }
  };

  const toggleAlertSelection = (id: number) => {
    setSelectedAlertIds((prev) =>
      prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id]
    );
  };

  const displayedMitreMappings: MitreMappingItem[] = showAllMitreRules
    ? platformMitre
    : selectedIncident?.mitre_mappings && selectedIncident.mitre_mappings.length > 0
    ? selectedIncident.mitre_mappings
    : platformMitre;

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-white">
            Incident Investigation & Threat Mapping Workspace
          </h1>
          <p className="text-xs text-slate-400">
            End-to-end case management, multi-alert correlation, forensic event evidence, investigation timeline, status tracking, and MITRE ATT&CK threat mapping
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setCreateModalOpen(true)}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-medium"
          >
            <FolderPlus className="w-3.5 h-3.5" />
            New Security Incident
          </button>
          <button
            onClick={loadIncidents}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-[#0f1623] hover:bg-[#151f32] border border-[#1e2c45] text-slate-200 text-xs"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Refresh
          </button>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="soc-panel p-4 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3 text-xs">
        <div className="lg:col-span-2">
          <label className="block text-[11px] text-slate-400 mb-1">
            Search Incidents (ID, Title, Description, Analyst)
          </label>
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-2.5" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search INC-2026, title, analyst..."
              className="w-full bg-[#090d16] border border-[#1e2c45] rounded pl-8 pr-2.5 py-1.5 text-slate-100"
            />
          </div>
        </div>

        <div>
          <label className="block text-[11px] text-slate-400 mb-1">Incident Status</label>
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="w-full bg-[#090d16] border border-[#1e2c45] rounded px-2.5 py-1.5 text-slate-100"
          >
            <option value="all">All Statuses</option>
            {INCIDENT_STATUSES.map((st) => (
              <option key={st} value={st}>
                {st}
              </option>
            ))}
          </select>
        </div>

        <div>
          <label className="block text-[11px] text-slate-400 mb-1">Severity</label>
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
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
          <label className="block text-[11px] text-slate-400 mb-1">Assigned Analyst</label>
          <select
            value={analystFilter}
            onChange={(e) => setAnalystFilter(e.target.value)}
            className="w-full bg-[#090d16] border border-[#1e2c45] rounded px-2.5 py-1.5 text-slate-100"
          >
            <option value="all">All Analysts</option>
            <option value="analyst">analyst (Marcus Vance)</option>
            <option value="ir.lead">ir.lead (Sarah Lin)</option>
            <option value="admin">admin (Elena Rostova)</option>
          </select>
        </div>
      </div>

      {feedback && (
        <div className="p-3 rounded bg-cyan-500/15 border border-cyan-500/40 text-cyan-200 text-xs flex items-center justify-between">
          <span>{feedback}</span>
          <button onClick={() => setFeedback(null)} className="text-cyan-400 hover:underline">
            Dismiss
          </button>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* Left List of Incidents */}
        <div className="lg:col-span-4 soc-panel overflow-hidden">
          <div className="px-4 py-3 border-b border-[#1e2c45] text-xs font-semibold text-white flex items-center justify-between">
            <span>Incidents Queue ({incidents.length})</span>
            {(statusFilter !== 'all' || severityFilter !== 'all' || analystFilter !== 'all' || search) && (
              <button
                onClick={() => {
                  setSearch('');
                  setStatusFilter('all');
                  setSeverityFilter('all');
                  setAnalystFilter('all');
                }}
                className="text-[11px] text-cyan-400 hover:underline"
              >
                Reset
              </button>
            )}
          </div>
          <div className="divide-y divide-[#1e2c45] max-h-[820px] overflow-y-auto">
            {loading ? (
              <div className="p-8 text-center text-xs text-slate-400">Loading incidents...</div>
            ) : incidents.length === 0 ? (
              <div className="p-8 text-center text-xs text-slate-400">No incidents found.</div>
            ) : (
              incidents.map((inc) => (
                <div
                  key={inc.id}
                  onClick={() => selectIncident(inc.id)}
                  className={`p-3.5 cursor-pointer space-y-1.5 text-xs ${
                    selectedIncident?.id === inc.id
                      ? 'bg-[#151f32] border-l-2 border-l-cyan-400'
                      : 'hover:bg-[#121b2c]'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-orange-400 font-semibold">
                      {inc.incident_id}
                    </span>
                    <div className="flex items-center gap-1.5">
                      <SeverityBadge severity={inc.severity} />
                      <IncidentStatusBadge status={inc.status} />
                    </div>
                  </div>
                  <div className="font-medium text-white">{inc.title}</div>
                  <div className="flex items-center justify-between text-[11px] text-slate-400">
                    <span className="flex items-center gap-1">
                      <UserCheck className="w-3 h-3 text-cyan-400" />
                      Analyst: <strong className="text-slate-200">{inc.assigned_analyst || 'Unassigned'}</strong>
                    </span>
                    <span>{inc.linked_alert_count} alert(s)</span>
                  </div>
                  <div className="flex items-center justify-between text-[10px] text-slate-500 font-mono">
                    <span>Evidence: {(inc.evidence_references || []).length} ref(s)</span>
                    <span>{formatTimestamp(inc.created_at)}</span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Right Detailed Incident Investigation Workspace */}
        <div className="lg:col-span-8 soc-panel p-5 space-y-5 text-xs">
          {!selectedIncident ? (
            <div className="py-16 text-center text-slate-400">
              Select an incident to open the investigation workspace.
            </div>
          ) : (
            <>
              {/* Incident Header & Lifecycle Stepper */}
              <div className="border-b border-[#1e2c45] pb-4 space-y-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-orange-400 font-bold text-sm">
                      {selectedIncident.incident_id}
                    </span>
                    <SeverityBadge severity={selectedIncident.severity} />
                    <IncidentStatusBadge status={selectedIncident.status} />
                    <span className="px-2 py-0.5 rounded bg-[#151f32] border border-[#243554] text-cyan-300 font-mono text-[11px]">
                      Assigned: {selectedIncident.assigned_analyst || 'Unassigned'}
                    </span>
                  </div>
                  <div className="flex items-center gap-3">
                    <div className="flex items-center gap-1.5">
                      <button
                        type="button"
                        onClick={() => handleOpenThreatIntel()}
                        className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-[#151f32] hover:bg-[#1e2c45] border border-cyan-500/40 text-cyan-300 text-[11px] font-medium"
                        title="Enrich incident with on-demand Threat Intelligence"
                      >
                        <Globe className="w-3.5 h-3.5 text-cyan-400" />
                        Enrich Threat Intel
                      </button>
                      <a
                        href={api.getIncidentCsvReportUrl(selectedIncident.incident_id)}
                        download
                        className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-[#151f32] hover:bg-[#1e2c45] border border-cyan-500/40 text-cyan-300 text-[11px] font-medium"
                        title="Export Incident Investigation Report (CSV)"
                      >
                        Export Incident CSV
                      </a>
                      <a
                        href={api.getIncidentPdfReportUrl(selectedIncident.incident_id)}
                        download
                        className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-cyan-600 hover:bg-cyan-500 text-white text-[11px] font-medium"
                        title="Export Incident Investigation Report (PDF)"
                      >
                        Export Incident PDF
                      </a>
                    </div>
                    <div className="text-right font-mono text-[11px] text-slate-400">
                      <div>Opened: {formatTimestamp(selectedIncident.created_at)}</div>
                      {selectedIncident.resolved_at && (
                        <div className="text-emerald-400">
                          Resolved: {formatTimestamp(selectedIncident.resolved_at)}
                        </div>
                      )}
                    </div>
                  </div>
                </div>
                <h2 className="text-base font-bold text-white">{selectedIncident.title}</h2>
                <p className="text-slate-300 leading-relaxed">{selectedIncident.description}</p>

                {/* Quick Lifecycle Status Progression Bar */}
                <div className="pt-2">
                  <div className="text-[10px] uppercase tracking-wider text-slate-400 mb-1.5">
                    Incident Response Lifecycle Status (Click to Transition)
                  </div>
                  <div className="grid grid-cols-5 gap-1.5">
                    {INCIDENT_STATUSES.map((st) => {
                      const active = selectedIncident.status === st;
                      return (
                        <button
                          key={st}
                          type="button"
                          onClick={() => handleQuickStatusChange(st)}
                          className={`py-1.5 px-2 rounded text-center font-medium border transition-colors ${
                            active
                              ? 'bg-cyan-500/20 border-cyan-400 text-cyan-200 font-semibold'
                              : 'bg-[#090d16] border-[#1e2c45] text-slate-400 hover:border-slate-500 hover:text-slate-200'
                          }`}
                        >
                          {st}
                        </button>
                      );
                    })}
                  </div>
                </div>
              </div>

              {/* Incident Workflow, Analyst Assignment & Resolution Form */}
              <form
                onSubmit={handleSaveIncidentUpdate}
                className="p-3.5 rounded bg-[#090d16] border border-[#1e2c45] space-y-3"
              >
                <div className="font-semibold text-white flex items-center gap-1.5">
                  <CheckCircle2 className="w-4 h-4 text-cyan-400" />
                  <span>Investigation Status, Analyst Assignment & Action Tracking</span>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                  <div>
                    <label className="block text-[11px] text-slate-400 mb-1">
                      Investigation Status
                    </label>
                    <select
                      value={editStatus}
                      onChange={(e) => setEditStatus(e.target.value as IncidentStatus)}
                      className="w-full bg-[#0f1623] border border-[#1e2c45] rounded px-2.5 py-1.5 text-white"
                    >
                      {INCIDENT_STATUSES.map((st) => (
                        <option key={st} value={st}>
                          {st}
                        </option>
                      ))}
                    </select>
                  </div>
                  <div>
                    <label className="block text-[11px] text-slate-400 mb-1">
                      Assigned SOC Analyst
                    </label>
                    <input
                      type="text"
                      list="soc-analysts-list"
                      value={editAssignee}
                      onChange={(e) => setEditAssignee(e.target.value)}
                      placeholder="analyst, ir.lead, admin..."
                      className="w-full bg-[#0f1623] border border-[#1e2c45] rounded px-2.5 py-1.5 text-white"
                    />
                    <datalist id="soc-analysts-list">
                      <option value="analyst">Marcus Vance (Senior Analyst)</option>
                      <option value="ir.lead">Sarah Lin (IR Lead)</option>
                      <option value="admin">Elena Rostova (SOC Director)</option>
                    </datalist>
                  </div>
                  <div>
                    <label className="block text-[11px] text-slate-400 mb-1">
                      Status Change / Action Comment
                    </label>
                    <input
                      type="text"
                      value={editStatusComment}
                      onChange={(e) => setEditStatusComment(e.target.value)}
                      placeholder="Reason for status or assignment update..."
                      className="w-full bg-[#0f1623] border border-[#1e2c45] rounded px-2.5 py-1.5 text-white"
                    />
                  </div>
                </div>
                <div>
                  <label className="block text-[11px] text-slate-400 mb-1">
                    Resolution & Containment Summary
                  </label>
                  <textarea
                    rows={2}
                    value={editResolution}
                    onChange={(e) => setEditResolution(e.target.value)}
                    placeholder="Document root cause, host containment actions, and remediation steps..."
                    className="w-full bg-[#0f1623] border border-[#1e2c45] rounded p-2 text-white"
                  />
                </div>
                <div className="flex justify-end">
                  <button
                    type="submit"
                    className="px-3.5 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-white font-medium"
                  >
                    Update Incident Record
                  </button>
                </div>
              </form>

              {/* Related Alerts & Link Additional Alert */}
              <div className="space-y-2">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <span className="font-semibold text-white flex items-center gap-1.5">
                    <Link2 className="w-4 h-4 text-cyan-400" />
                    Associated Alerts ({selectedIncident.related_alerts.length})
                  </span>
                  <div className="flex items-center gap-2">
                    <select
                      value={alertIdToLink}
                      onChange={(e) => setAlertIdToLink(e.target.value)}
                      className="bg-[#090d16] border border-[#1e2c45] rounded px-2 py-1 text-slate-200 text-[11px]"
                    >
                      <option value="">Associate another alert...</option>
                      {availableAlerts.map((a) => (
                        <option key={a.id} value={a.id}>
                          {a.alert_id} ({a.rule_code}) — {a.title.slice(0, 42)}
                        </option>
                      ))}
                    </select>
                    <button
                      type="button"
                      onClick={handleLinkAlert}
                      disabled={!alertIdToLink}
                      className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-[#151f32] hover:bg-cyan-600 border border-cyan-500/40 text-white text-[11px] disabled:opacity-40"
                    >
                      <Plus className="w-3 h-3" />
                      Link Alert
                    </button>
                  </div>
                </div>

                {selectedIncident.related_alerts.length === 0 ? (
                  <div className="p-3 rounded bg-[#090d16] border border-[#1e2c45] text-slate-400">
                    No alerts currently associated with this incident. Use the selector above to associate security alerts.
                  </div>
                ) : (
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                    {selectedIncident.related_alerts.map((al) => (
                      <div
                        key={al.id}
                        className="p-2.5 rounded bg-[#151f32] border border-[#243554] hover:border-cyan-500/40 space-y-1"
                      >
                        <div className="flex items-center justify-between">
                          <button
                            type="button"
                            onClick={() => navigate(`/alerts?alertId=${al.id}`)}
                            className="font-mono text-cyan-400 font-semibold hover:underline"
                          >
                            {al.alert_id}
                          </button>
                          <div className="flex items-center gap-1">
                            <SeverityBadge severity={al.severity} />
                            <AlertStatusBadge status={al.status} />
                            <button
                              type="button"
                              onClick={() => handleUnlinkAlert(al.id, al.alert_id)}
                              title="Unlink alert from incident"
                              className="p-1 text-slate-400 hover:text-red-400"
                            >
                              <Trash2 className="w-3 h-3" />
                            </button>
                          </div>
                        </div>
                        <div
                          onClick={() => navigate(`/alerts?alertId=${al.id}`)}
                          className="font-medium text-white cursor-pointer"
                        >
                          {al.title}
                        </div>
                        <div className="flex flex-wrap items-center justify-between gap-1 text-[11px] text-slate-400 font-mono">
                          <span className="flex items-center gap-1.5">
                            {al.rule_code} • IP: {al.source_ip || '—'}
                            {al.source_ip && (
                              <button
                                type="button"
                                onClick={() => handleOpenThreatIntel(al.source_ip!)}
                                className="text-cyan-400 hover:underline flex items-center gap-0.5 text-[10px]"
                                title="Check Threat Intel for this IP"
                              >
                                <Globe className="w-2.5 h-2.5" /> TI
                              </button>
                            )}
                          </span>
                          {al.mitre_technique_id && (
                            <span className="text-blue-300">
                              {al.mitre_tactic}: {al.mitre_technique_id}
                            </span>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* MITRE ATT&CK Threat Mapping Section */}
              <div className="space-y-2.5 p-3.5 rounded bg-[#090d16] border border-[#1e2c45]">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div className="flex items-center gap-1.5 font-semibold text-white">
                    <ShieldAlert className="w-4 h-4 text-cyan-400" />
                    <span>
                      MITRE ATT&CK Threat Mapping (
                      {showAllMitreRules ? 'All Detection Rules' : 'Incident Attack Chain'})
                    </span>
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      onClick={() => setShowAllMitreRules((prev) => !prev)}
                      className="px-2 py-0.5 rounded bg-[#151f32] border border-[#243554] text-cyan-300 text-[11px] hover:border-cyan-500/40"
                    >
                      {showAllMitreRules
                        ? 'Show Incident Techniques Only'
                        : 'Show Full 7-Rule MITRE Matrix'}
                    </button>
                    <button
                      type="button"
                      onClick={() => navigate('/rules?tab=mitre')}
                      className="text-[11px] text-cyan-400 hover:underline"
                    >
                      Open MITRE Matrix →
                    </button>
                  </div>
                </div>

                {displayedMitreMappings.length === 0 ? (
                  <div className="text-slate-400 text-[11px]">
                    No MITRE ATT&CK mappings available yet.
                  </div>
                ) : (
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
                    {displayedMitreMappings.map((m, idx) => {
                      const rulesList =
                        m.associated_rules && m.associated_rules.length > 0
                          ? m.associated_rules
                          : m.rule
                          ? [m.rule]
                          : [];
                      return (
                        <div
                          key={`${m.technique_id}-${idx}`}
                          className="p-3 rounded bg-[#151f32] border border-[#243554] space-y-2"
                        >
                          <div className="flex items-start justify-between gap-2">
                            <div>
                              <div className="flex flex-wrap items-center gap-1.5">
                                <span className="px-1.5 py-0.5 rounded bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 font-mono text-[11px] font-bold">
                                  {m.technique_id}
                                </span>
                                <span className="px-1.5 py-0.5 rounded bg-blue-500/15 text-blue-300 border border-blue-500/30 font-mono text-[10px] uppercase">
                                  {m.tactic_id ? `${m.tactic_id} • ` : ''}
                                  {m.tactic}
                                </span>
                              </div>
                              <div className="font-semibold text-white mt-1">
                                {m.technique_name}
                              </div>
                            </div>
                            {m.reference_url && (
                              <a
                                href={m.reference_url}
                                target="_blank"
                                rel="noreferrer"
                                className="inline-flex items-center gap-1 text-[10px] text-cyan-400 hover:underline shrink-0"
                              >
                                MITRE
                                <ExternalLink className="w-3 h-3" />
                              </a>
                            )}
                          </div>

                          {/* Associated Detection Rules */}
                          <div className="text-[11px] space-y-1">
                            <div className="text-[10px] uppercase text-slate-400">
                              Associated Detection Rule(s)
                            </div>
                            {rulesList.map((r) => (
                              <div
                                key={r.rule_id}
                                className="flex items-center justify-between bg-[#090d16] px-2 py-1 rounded border border-[#1e2c45]"
                              >
                                <span className="truncate pr-2">
                                  <span className="font-mono text-cyan-400 mr-1.5">
                                    {r.rule_id}
                                  </span>
                                  <span className="text-slate-200">{r.name}</span>
                                </span>
                                <SeverityBadge severity={r.severity} />
                              </div>
                            ))}
                          </div>

                          {/* Related Alerts */}
                          <div className="text-[11px] space-y-1">
                            <div className="text-[10px] uppercase text-slate-400">
                              Related Alerts ({m.related_alerts?.length || 0})
                            </div>
                            {!m.related_alerts || m.related_alerts.length === 0 ? (
                              <div className="text-slate-500 italic text-[10px]">
                                No triggered alerts linked to this technique.
                              </div>
                            ) : (
                              <div className="flex flex-wrap gap-1">
                                {m.related_alerts.slice(0, 4).map((ra) => (
                                  <button
                                    key={ra.id}
                                    type="button"
                                    onClick={() => navigate(`/alerts?alertId=${ra.id}`)}
                                    className="px-2 py-0.5 rounded bg-[#090d16] border border-[#1e2c45] hover:border-cyan-500/40 font-mono text-[10px] text-cyan-300"
                                    title={ra.title}
                                  >
                                    {ra.alert_id}
                                  </button>
                                ))}
                              </div>
                            )}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>

              {/* Correlated Security Events Across Incident */}
              <div className="space-y-2">
                <div className="font-semibold text-white">
                  Related Security Events ({selectedIncident.related_events.length})
                </div>
                <div className="border border-[#1e2c45] rounded overflow-hidden max-h-52 overflow-y-auto">
                  <table className="w-full text-left border-collapse text-[11px]">
                    <thead>
                      <tr className="bg-[#0c121e] border-b border-[#1e2c45] text-slate-400 uppercase">
                        <th className="py-1.5 px-2.5">Event ID</th>
                        <th className="py-1.5 px-2.5">Timestamp</th>
                        <th className="py-1.5 px-2.5">Category / Type</th>
                        <th className="py-1.5 px-2.5">Source IP</th>
                        <th className="py-1.5 px-2.5">User / Host</th>
                        <th className="py-1.5 px-2.5">Status</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#1e2c45]">
                      {selectedIncident.related_events.length === 0 ? (
                        <tr>
                          <td colSpan={6} className="py-4 text-center text-slate-500">
                            No correlated security events linked yet.
                          </td>
                        </tr>
                      ) : (
                        selectedIncident.related_events.map((ev) => (
                          <tr
                            key={ev.id}
                            onClick={() =>
                              navigate(`/events?search=${encodeURIComponent(ev.event_id)}`)
                            }
                            className="hover:bg-[#151f32] cursor-pointer"
                          >
                            <td className="py-1.5 px-2.5 font-mono text-cyan-400">
                              {ev.event_id}
                            </td>
                            <td className="py-1.5 px-2.5 font-mono text-slate-300">
                              {formatTimestamp(ev.timestamp)}
                            </td>
                            <td className="py-1.5 px-2.5 text-slate-200">
                              {ev.event_category}: {ev.event_type} ({ev.action})
                            </td>
                            <td className="py-1.5 px-2.5 font-mono text-slate-300">
                              {ev.source_ip}
                            </td>
                            <td className="py-1.5 px-2.5 text-slate-300">
                              {ev.username || '—'} @ {ev.hostname || '—'}
                            </td>
                            <td className="py-1.5 px-2.5 font-mono text-slate-300">
                              {ev.status}
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Evidence References Maintenance */}
              <div className="space-y-2.5 p-3.5 rounded bg-[#090d16] border border-[#1e2c45]">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-white flex items-center gap-1.5">
                    <FileCheck2 className="w-4 h-4 text-cyan-400" />
                    <span>
                      Evidence References & Forensic Artifacts (
                      {(selectedIncident.evidence_references || []).length})
                    </span>
                  </span>
                  <span className="text-[10px] font-mono text-slate-400">
                    CHAIN OF CUSTODY
                  </span>
                </div>

                <form
                  onSubmit={handleAddEvidence}
                  className="grid grid-cols-1 sm:grid-cols-12 gap-2"
                >
                  <select
                    value={evidenceType}
                    onChange={(e) => setEvidenceType(e.target.value)}
                    className="sm:col-span-2 bg-[#0f1623] border border-[#1e2c45] rounded px-2 py-1.5 text-white text-[11px]"
                  >
                    <option value="event">Event</option>
                    <option value="alert">Alert</option>
                    <option value="ioc">IOC</option>
                    <option value="artifact">Artifact</option>
                    <option value="log">Log</option>
                  </select>
                  <input
                    type="text"
                    value={evidenceRef}
                    onChange={(e) => setEvidenceRef(e.target.value)}
                    placeholder="Reference ID (EVT-..., ALT-..., IP, SHA256)..."
                    className="sm:col-span-4 bg-[#0f1623] border border-[#1e2c45] rounded px-2.5 py-1.5 text-white font-mono text-[11px]"
                  />
                  <input
                    type="text"
                    value={evidenceDesc}
                    onChange={(e) => setEvidenceDesc(e.target.value)}
                    placeholder="Forensic description / relevance..."
                    className="sm:col-span-4 bg-[#0f1623] border border-[#1e2c45] rounded px-2.5 py-1.5 text-white text-[11px]"
                  />
                  <button
                    type="submit"
                    className="sm:col-span-2 px-2.5 py-1.5 rounded bg-[#151f32] hover:bg-cyan-600 border border-cyan-500/40 text-white font-medium text-[11px]"
                  >
                    + Add Evidence
                  </button>
                </form>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 max-h-44 overflow-y-auto">
                  {(selectedIncident.evidence_references || []).map((ref, idx) => (
                    <div
                      key={`${ref.type}-${ref.reference}-${idx}`}
                      className="p-2 rounded bg-[#151f32] border border-[#243554] flex items-start justify-between gap-2"
                    >
                      <div className="min-w-0">
                        <div className="flex items-center gap-1.5">
                          <span className="px-1.5 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800/60 font-mono text-[10px] uppercase">
                            {ref.type}
                          </span>
                          <span className="font-mono text-white font-semibold truncate">
                            {ref.reference}
                          </span>
                        </div>
                        <div className="text-[11px] text-slate-300 truncate mt-0.5">
                          {ref.description}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Investigation Timeline & Analyst Notes */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {/* Timeline */}
                <div className="space-y-2">
                  <div className="font-semibold text-white flex items-center gap-1.5">
                    <Clock className="w-4 h-4 text-cyan-400" />
                    <span>
                      Investigation Timeline & Actions (
                      {selectedIncident.timeline_events.length})
                    </span>
                  </div>
                  <div className="space-y-2.5 max-h-64 overflow-y-auto pl-2">
                    {selectedIncident.timeline_events.map((t, idx) => (
                      <div
                        key={idx}
                        className="pl-3 border-l-2 border-cyan-500/40 space-y-0.5"
                      >
                        <div className="flex items-center justify-between text-[10px] text-slate-400">
                          <span className="font-semibold text-cyan-300">{t.action}</span>
                          <span className="font-mono">{formatTimestamp(t.timestamp)}</span>
                        </div>
                        {t.new_status && (
                          <div className="text-[10px] font-mono text-orange-300">
                            {t.previous_status ? `${t.previous_status} → ` : 'Initial: '}
                            {t.new_status}
                          </div>
                        )}
                        <div className="text-slate-200">{t.detail}</div>
                        <div className="text-[10px] text-slate-500">Actor: {t.actor}</div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Notes */}
                <div className="space-y-2">
                  <div className="font-semibold text-white flex items-center gap-1.5">
                    <MessageSquare className="w-4 h-4 text-blue-400" />
                    <span>Incident Analyst Notes ({selectedIncident.notes.length})</span>
                  </div>
                  <form onSubmit={handleAddIncidentNote} className="space-y-2">
                    <div className="flex gap-2">
                      <select
                        value={noteType}
                        onChange={(e) => setNoteType(e.target.value)}
                        className="bg-[#090d16] border border-[#1e2c45] rounded px-2 py-1.5 text-slate-200 text-[11px]"
                      >
                        <option value="investigation_note">Investigation</option>
                        <option value="containment_action">Containment</option>
                        <option value="forensic_finding">Forensic</option>
                        <option value="handover_note">Handover</option>
                      </select>
                      <input
                        type="text"
                        value={noteText}
                        onChange={(e) => setNoteText(e.target.value)}
                        placeholder="Add investigation finding..."
                        className="flex-1 bg-[#090d16] border border-[#1e2c45] rounded px-2.5 py-1.5 text-white"
                      />
                      <button
                        type="submit"
                        className="px-3 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-white font-medium"
                      >
                        Post
                      </button>
                    </div>
                  </form>
                  <div className="space-y-2 max-h-52 overflow-y-auto">
                    {selectedIncident.notes.length === 0 ? (
                      <div className="text-slate-500 italic">
                        No investigation notes recorded yet.
                      </div>
                    ) : (
                      selectedIncident.notes.map((n) => (
                        <div
                          key={n.id}
                          className="p-2.5 rounded bg-[#090d16] border border-[#1e2c45] space-y-1"
                        >
                          <div className="flex items-center justify-between text-[10px] text-slate-400">
                            <span className="text-cyan-400 font-semibold">
                              {n.author}{' '}
                              <span className="text-slate-500 font-mono">({n.note_type})</span>
                            </span>
                            <span className="font-mono">{formatTimestamp(n.created_at)}</span>
                          </div>
                          <p className="text-slate-200">{n.content}</p>
                        </div>
                      ))
                    )}
                  </div>
                </div>
              </div>
            </>
          )}
        </div>
      </div>

      {/* Create New Incident Modal */}
      {createModalOpen && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
          <div className="soc-panel w-full max-w-xl p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-[#1e2c45] pb-3">
              <h3 className="text-sm font-semibold text-white">
                Create Security Incident & Correlate Alerts
              </h3>
              <button
                onClick={() => setCreateModalOpen(false)}
                className="text-slate-400 hover:text-white"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
            <form onSubmit={handleCreateIncident} className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-400 mb-1">Incident Title</label>
                <input
                  type="text"
                  value={newIncTitle}
                  onChange={(e) => setNewIncTitle(e.target.value)}
                  placeholder="e.g. Compromised DevOps Account & Lateral Movement"
                  className="w-full bg-[#090d16] border border-[#1e2c45] rounded px-3 py-1.5 text-white"
                  required
                />
              </div>
              <div className="grid grid-cols-3 gap-3">
                <div>
                  <label className="block text-slate-400 mb-1">Severity</label>
                  <select
                    value={newIncSeverity}
                    onChange={(e) => setNewIncSeverity(e.target.value)}
                    className="w-full bg-[#090d16] border border-[#1e2c45] rounded px-2.5 py-1.5 text-white"
                  >
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                  </select>
                </div>
                <div>
                  <label className="block text-slate-400 mb-1">Initial Status</label>
                  <select
                    value={newIncStatus}
                    onChange={(e) => setNewIncStatus(e.target.value as IncidentStatus)}
                    className="w-full bg-[#090d16] border border-[#1e2c45] rounded px-2.5 py-1.5 text-white"
                  >
                    {INCIDENT_STATUSES.map((st) => (
                      <option key={st} value={st}>
                        {st}
                      </option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="block text-slate-400 mb-1">Assigned Analyst</label>
                  <input
                    type="text"
                    value={newIncAssignee}
                    onChange={(e) => setNewIncAssignee(e.target.value)}
                    className="w-full bg-[#090d16] border border-[#1e2c45] rounded px-2.5 py-1.5 text-white"
                  />
                </div>
              </div>
              <div>
                <label className="block text-slate-400 mb-1">Description & Scope</label>
                <textarea
                  rows={3}
                  value={newIncDesc}
                  onChange={(e) => setNewIncDesc(e.target.value)}
                  placeholder="Initial triage hypothesis and affected assets..."
                  className="w-full bg-[#090d16] border border-[#1e2c45] rounded p-2 text-white"
                  required
                />
              </div>
              <div>
                <label className="block text-slate-400 mb-1">
                  Associate Existing Alerts ({selectedAlertIds.length} selected)
                </label>
                <div className="max-h-36 overflow-y-auto border border-[#1e2c45] rounded p-2 space-y-1 bg-[#090d16]">
                  {availableAlerts.map((a) => (
                    <label
                      key={a.id}
                      className="flex items-center gap-2 p-1 rounded hover:bg-[#151f32] cursor-pointer"
                    >
                      <input
                        type="checkbox"
                        checked={selectedAlertIds.includes(a.id)}
                        onChange={() => toggleAlertSelection(a.id)}
                      />
                      <span className="font-mono text-cyan-400">{a.alert_id}</span>
                      <span className="font-mono text-[10px] text-slate-400">
                        ({a.rule_code})
                      </span>
                      <span className="text-slate-200 truncate">{a.title}</span>
                    </label>
                  ))}
                </div>
              </div>
              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setCreateModalOpen(false)}
                  className="px-3 py-1.5 rounded border border-[#1e2c45] text-slate-300"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-white font-medium"
                >
                  Open Incident
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* On-Demand Threat Intelligence Enrichment Modal */}
      <ThreatIntelModal
        isOpen={threatIntelOpen}
        onClose={() => setThreatIntelOpen(false)}
        initialIp={threatIntelIp}
        onAttachEvidenceNote={handleAttachIntelToIncident}
      />
    </div>
  );
};
