import React, { useCallback, useEffect, useState } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import {
  ArrowUpDown,
  ChevronLeft,
  ChevronRight,
  Code2,
  FileText,
  Filter,
  GitBranch,
  PlusCircle,
  RefreshCw,
  Search,
  X,
} from 'lucide-react';
import { api } from '../services/api';
import { SecurityEvent } from '../types';
import { SeverityBadge } from '../components/SeverityBadge';
import { formatTimestamp } from '../utils/formatters';

export const SecurityEventsExplorerPage: React.FC = () => {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();

  // Filter state
  const [search, setSearch] = useState(searchParams.get('search') || '');
  const [sourceIp, setSourceIp] = useState(searchParams.get('source_ip') || '');
  const [username, setUsername] = useState(searchParams.get('username') || '');
  const [hostname, setHostname] = useState(searchParams.get('hostname') || '');
  const [category, setCategory] = useState(searchParams.get('event_category') || 'all');
  const [severity, setSeverity] = useState(searchParams.get('severity') || 'all');
  const [statusFilter, setStatusFilter] = useState(searchParams.get('status') || 'all');
  const [startTime, setStartTime] = useState('');
  const [endTime, setEndTime] = useState('');
  const [sortBy, setSortBy] = useState<string>('timestamp');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc');
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);

  // Data state
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [total, setTotal] = useState(0);
  const [totalPages, setTotalPages] = useState(1);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Event Details Drawer state
  const [selectedEventId, setSelectedEventId] = useState<number | string | null>(null);
  const [drawerData, setDrawerData] = useState<{
    event: SecurityEvent;
    related_events: SecurityEvent[];
    linked_alerts: any[];
  } | null>(null);
  const [drawerLoading, setDrawerLoading] = useState(false);

  // Custom Event Ingest Modal
  const [ingestModalOpen, setIngestModalOpen] = useState(false);
  const [customEventForm, setCustomEventForm] = useState({
    source_ip: '185.220.101.42',
    destination_ip: '10.20.0.15',
    destination_port: '22',
    username: 'root',
    hostname: 'prod-vault-01',
    event_category: 'Authentication',
    event_type: 'ssh_auth_failure',
    action: 'password_login',
    status: 'failure',
    severity: 'high',
    raw_log: '[SYNTHETIC] Nov 09 20:30:00 prod-vault-01 sshd[9901]: Failed password for root from 185.220.101.42 port 50122 ssh2',
  });
  const [ingestResultMsg, setIngestResultMsg] = useState<string | null>(null);

  const fetchEvents = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.listEvents({
        search: search.trim() || undefined,
        source_ip: sourceIp.trim() || undefined,
        username: username.trim() || undefined,
        hostname: hostname.trim() || undefined,
        event_category: category,
        severity,
        status: statusFilter,
        start_time: startTime ? new Date(startTime).toISOString() : undefined,
        end_time: endTime ? new Date(endTime).toISOString() : undefined,
        sort_by: sortBy,
        sort_order: sortOrder,
        page,
        page_size: pageSize,
      });
      setEvents(res.items);
      setTotal(res.total);
      setTotalPages(res.total_pages);
    } catch (err: any) {
      setError(err.message || 'Failed to load security events');
    } finally {
      setLoading(false);
    }
  }, [
    search,
    sourceIp,
    username,
    hostname,
    category,
    severity,
    statusFilter,
    startTime,
    endTime,
    sortBy,
    sortOrder,
    page,
    pageSize,
  ]);

  const handleSortColumn = (col: string) => {
    if (sortBy === col) {
      setSortOrder((prev) => (prev === 'desc' ? 'asc' : 'desc'));
    } else {
      setSortBy(col);
      setSortOrder('desc');
    }
    setPage(1);
  };

  useEffect(() => {
    fetchEvents();
  }, [fetchEvents]);

  const openEventDrawer = async (eventId: number | string) => {
    setSelectedEventId(eventId);
    setDrawerLoading(true);
    try {
      const detail = await api.getEventDetail(eventId);
      setDrawerData(detail);
    } catch {
      setDrawerData(null);
    } finally {
      setDrawerLoading(false);
    }
  };

  const handleResetFilters = () => {
    setSearch('');
    setSourceIp('');
    setUsername('');
    setHostname('');
    setCategory('all');
    setSeverity('all');
    setStatusFilter('all');
    setStartTime('');
    setEndTime('');
    setPage(1);
    setSearchParams({});
  };

  const handleIngestSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIngestResultMsg(null);
    try {
      const res = await api.ingestEvent({
        ...customEventForm,
        destination_port: customEventForm.destination_port
          ? Number(customEventForm.destination_port)
          : null,
        is_synthetic: true,
        metadata: {
          is_synthetic: true,
          scenario: 'manual_analyst_test',
          ground_truth: 'malicious',
        },
      });
      setIngestResultMsg(
        `Ingested ${res.event.event_id} (${res.generated_alerts_count} alert(s) triggered)`
      );
      fetchEvents();
    } catch (err: any) {
      setIngestResultMsg(`Error: ${err.message}`);
    }
  };

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-white">Security Events Explorer</h1>
          <p className="text-xs text-slate-400">
            High-speed telemetry search, multi-facet filtering, raw log inspection, and related-event correlation
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setIngestModalOpen(true)}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-medium"
          >
            <PlusCircle className="w-3.5 h-3.5" />
            Ingest Custom Event
          </button>
          <button
            onClick={fetchEvents}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-[#0f1623] hover:bg-[#151f32] border border-[#1e2c45] text-slate-200 text-xs"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Refresh
          </button>
        </div>
      </div>

      {/* Multi-Facet Search & Filter Bar */}
      <div className="soc-panel p-4 space-y-3">
        <div className="flex items-center justify-between text-xs text-slate-400">
          <span className="flex items-center gap-1.5 font-semibold uppercase tracking-wider text-slate-300">
            <Filter className="w-3.5 h-3.5 text-cyan-400" />
            Telemetry Query Filters
          </span>
          <button onClick={handleResetFilters} className="text-cyan-400 hover:underline">
            Reset All Filters
          </button>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs">
          <div>
            <label className="block text-[11px] text-slate-400 mb-1">
              Keyword / Event ID / Raw Log
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
                placeholder="Search event_id, action, log..."
                className="w-full bg-[#090d16] border border-[#1e2c45] rounded pl-8 pr-2.5 py-1.5 text-slate-100"
              />
            </div>
          </div>

          <div>
            <label className="block text-[11px] text-slate-400 mb-1">Source IP Address</label>
            <input
              type="text"
              value={sourceIp}
              onChange={(e) => {
                setSourceIp(e.target.value);
                setPage(1);
              }}
              placeholder="e.g. 185.220.101.42"
              className="w-full bg-[#090d16] border border-[#1e2c45] rounded px-2.5 py-1.5 font-mono text-slate-100"
            />
          </div>

          <div>
            <label className="block text-[11px] text-slate-400 mb-1">Username</label>
            <input
              type="text"
              value={username}
              onChange={(e) => {
                setUsername(e.target.value);
                setPage(1);
              }}
              placeholder="e.g. svc_backup_admin"
              className="w-full bg-[#090d16] border border-[#1e2c45] rounded px-2.5 py-1.5 text-slate-100"
            />
          </div>

          <div>
            <label className="block text-[11px] text-slate-400 mb-1">Hostname</label>
            <input
              type="text"
              value={hostname}
              onChange={(e) => {
                setHostname(e.target.value);
                setPage(1);
              }}
              placeholder="e.g. prod-vault-01"
              className="w-full bg-[#090d16] border border-[#1e2c45] rounded px-2.5 py-1.5 text-slate-100"
            />
          </div>

          <div>
            <label className="block text-[11px] text-slate-400 mb-1">Event Category</label>
            <select
              value={category}
              onChange={(e) => {
                setCategory(e.target.value);
                setPage(1);
              }}
              className="w-full bg-[#090d16] border border-[#1e2c45] rounded px-2.5 py-1.5 text-slate-100"
            >
              <option value="all">All Categories</option>
              <option value="Authentication">Authentication</option>
              <option value="Authorization">Authorization</option>
              <option value="Network">Network</option>
              <option value="Endpoint">Endpoint</option>
              <option value="System">System</option>
              <option value="Application">Application</option>
            </select>
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
              <option value="info">Info</option>
            </select>
          </div>

          <div>
            <label className="block text-[11px] text-slate-400 mb-1">Event Status</label>
            <select
              value={statusFilter}
              onChange={(e) => {
                setStatusFilter(e.target.value);
                setPage(1);
              }}
              className="w-full bg-[#090d16] border border-[#1e2c45] rounded px-2.5 py-1.5 text-slate-100"
            >
              <option value="all">All Statuses</option>
              <option value="success">Success</option>
              <option value="failure">Failure</option>
              <option value="blocked">Blocked</option>
              <option value="allowed">Allowed</option>
            </select>
          </div>

          <div className="grid grid-cols-2 gap-2">
            <div>
              <label className="block text-[11px] text-slate-400 mb-1">From Time</label>
              <input
                type="datetime-local"
                value={startTime}
                onChange={(e) => {
                  setStartTime(e.target.value);
                  setPage(1);
                }}
                className="w-full bg-[#090d16] border border-[#1e2c45] rounded px-2 py-1.5 text-[11px] text-slate-200"
              />
            </div>
            <div>
              <label className="block text-[11px] text-slate-400 mb-1">To Time</label>
              <input
                type="datetime-local"
                value={endTime}
                onChange={(e) => {
                  setEndTime(e.target.value);
                  setPage(1);
                }}
                className="w-full bg-[#090d16] border border-[#1e2c45] rounded px-2 py-1.5 text-[11px] text-slate-200"
              />
            </div>
          </div>
        </div>
      </div>

      {/* Events Table */}
      <div className="soc-panel overflow-hidden">
        <div className="px-4 py-3 border-b border-[#1e2c45] flex items-center justify-between text-xs">
          <div className="text-slate-300">
            Showing <span className="font-mono font-semibold text-white">{events.length}</span> of{' '}
            <span className="font-mono font-semibold text-cyan-400">{total}</span> matching security events
          </div>
          <div className="flex items-center gap-2">
            <span className="text-slate-400">Rows:</span>
            <select
              value={pageSize}
              onChange={(e) => {
                setPageSize(Number(e.target.value));
                setPage(1);
              }}
              className="bg-[#090d16] border border-[#1e2c45] rounded px-2 py-1 text-slate-200"
            >
              <option value={15}>15</option>
              <option value={25}>25</option>
              <option value={50}>50</option>
              <option value={100}>100</option>
            </select>
          </div>
        </div>

        {error && (
          <div className="p-4 text-xs text-red-300 bg-red-950/20 border-b border-red-500/30">
            {error}
          </div>
        )}

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="bg-[#0c121e] border-b border-[#1e2c45] text-slate-400 text-[11px] uppercase">
                <th className="py-2.5 px-3">Event ID</th>
                <th
                  onClick={() => handleSortColumn('timestamp')}
                  className="py-2.5 px-3 cursor-pointer hover:text-cyan-300 select-none"
                >
                  <span className="inline-flex items-center gap-1">
                    Timestamp (UTC)
                    <ArrowUpDown className="w-3 h-3 text-cyan-400" />
                  </span>
                </th>
                <th
                  onClick={() => handleSortColumn('event_category')}
                  className="py-2.5 px-3 cursor-pointer hover:text-cyan-300 select-none"
                >
                  <span className="inline-flex items-center gap-1">
                    Category
                    <ArrowUpDown className="w-3 h-3 text-cyan-400" />
                  </span>
                </th>
                <th
                  onClick={() => handleSortColumn('event_type')}
                  className="py-2.5 px-3 cursor-pointer hover:text-cyan-300 select-none"
                >
                  <span className="inline-flex items-center gap-1">
                    Event Type / Action
                    <ArrowUpDown className="w-3 h-3 text-cyan-400" />
                  </span>
                </th>
                <th
                  onClick={() => handleSortColumn('source_ip')}
                  className="py-2.5 px-3 cursor-pointer hover:text-cyan-300 select-none"
                >
                  <span className="inline-flex items-center gap-1">
                    Source IP → Dest
                    <ArrowUpDown className="w-3 h-3 text-cyan-400" />
                  </span>
                </th>
                <th
                  onClick={() => handleSortColumn('username')}
                  className="py-2.5 px-3 cursor-pointer hover:text-cyan-300 select-none"
                >
                  <span className="inline-flex items-center gap-1">
                    Username / Host
                    <ArrowUpDown className="w-3 h-3 text-cyan-400" />
                  </span>
                </th>
                <th
                  onClick={() => handleSortColumn('status')}
                  className="py-2.5 px-3 cursor-pointer hover:text-cyan-300 select-none"
                >
                  <span className="inline-flex items-center gap-1">
                    Status
                    <ArrowUpDown className="w-3 h-3 text-cyan-400" />
                  </span>
                </th>
                <th
                  onClick={() => handleSortColumn('severity')}
                  className="py-2.5 px-3 cursor-pointer hover:text-cyan-300 select-none"
                >
                  <span className="inline-flex items-center gap-1">
                    Severity
                    <ArrowUpDown className="w-3 h-3 text-cyan-400" />
                  </span>
                </th>
                <th className="py-2.5 px-3">Telemetry</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1e2c45]">
              {loading ? (
                <tr>
                  <td colSpan={9} className="py-8 text-center text-slate-400">
                    Querying PostgreSQL security_events table...
                  </td>
                </tr>
              ) : events.length === 0 ? (
                <tr>
                  <td colSpan={9} className="py-8 text-center text-slate-400">
                    No security events match the current filter criteria.
                  </td>
                </tr>
              ) : (
                events.map((ev) => (
                  <tr
                    key={ev.id}
                    onClick={() => openEventDrawer(ev.id)}
                    className={`hover:bg-[#151f32] cursor-pointer transition-colors ${
                      selectedEventId === ev.id ? 'bg-[#151f32]' : ''
                    }`}
                  >
                    <td className="py-2.5 px-3 font-mono text-cyan-400 whitespace-nowrap">
                      {ev.event_id}
                    </td>
                    <td className="py-2.5 px-3 font-mono text-[11px] text-slate-300 whitespace-nowrap">
                      {formatTimestamp(ev.timestamp)}
                    </td>
                    <td className="py-2.5 px-3 text-slate-200">{ev.event_category}</td>
                    <td className="py-2.5 px-3">
                      <div className="font-mono text-slate-100">{ev.event_type}</div>
                      <div className="text-[11px] text-slate-400">{ev.action}</div>
                    </td>
                    <td className="py-2.5 px-3 font-mono text-slate-300 whitespace-nowrap">
                      <span>{ev.source_ip}</span>
                      {ev.destination_ip && (
                        <span className="text-slate-500">
                          {' '}
                          → {ev.destination_ip}
                          {ev.destination_port ? `:${ev.destination_port}` : ''}
                        </span>
                      )}
                    </td>
                    <td className="py-2.5 px-3 text-slate-300">
                      <div>{ev.username || '—'}</div>
                      <div className="text-[11px] text-slate-500 font-mono">
                        {ev.hostname || '—'}
                      </div>
                    </td>
                    <td className="py-2.5 px-3">
                      <span
                        className={`px-2 py-0.5 rounded font-mono text-[11px] ${
                          ev.status === 'failure' || ev.status === 'blocked'
                            ? 'bg-red-500/15 text-red-300'
                            : 'bg-emerald-500/15 text-emerald-300'
                        }`}
                      >
                        {ev.status}
                      </span>
                    </td>
                    <td className="py-2.5 px-3">
                      <SeverityBadge severity={ev.severity} />
                    </td>
                    <td className="py-2.5 px-3">
                      {ev.is_synthetic ? (
                        <span className="px-1.5 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800/60 font-mono text-[10px]">
                          SYNTHETIC
                        </span>
                      ) : (
                        <span className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 font-mono text-[10px]">
                          ORGANIC
                        </span>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Controls */}
        <div className="px-4 py-3 border-t border-[#1e2c45] flex items-center justify-between text-xs">
          <div className="text-slate-400">
            Page <span className="text-white font-semibold">{page}</span> of{' '}
            <span className="text-white font-semibold">{totalPages}</span>
          </div>
          <div className="flex items-center gap-2">
            <button
              disabled={page <= 1}
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-[#090d16] border border-[#1e2c45] disabled:opacity-40 text-slate-200 hover:bg-[#151f32]"
            >
              <ChevronLeft className="w-3.5 h-3.5" />
              Prev
            </button>
            <button
              disabled={page >= totalPages}
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-[#090d16] border border-[#1e2c45] disabled:opacity-40 text-slate-200 hover:bg-[#151f32]"
            >
              Next
              <ChevronRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>

      {/* Event Details Inspection Drawer */}
      {selectedEventId && (
        <div className="fixed inset-y-0 right-0 w-full max-w-2xl bg-[#0c121e] border-l border-[#243554] shadow-2xl z-50 flex flex-col">
          <div className="px-5 py-4 border-b border-[#1e2c45] flex items-center justify-between">
            <div>
              <div className="text-xs font-mono text-cyan-400">
                SECURITY EVENT FORENSIC DRAWER
              </div>
              <h2 className="text-base font-bold text-white">
                {drawerData?.event.event_id || 'Loading event...'}
              </h2>
            </div>
            <button
              onClick={() => {
                setSelectedEventId(null);
                setDrawerData(null);
              }}
              className="p-1.5 rounded bg-[#151f32] text-slate-300 hover:text-white"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          <div className="flex-1 overflow-y-auto p-5 space-y-5 text-xs">
            {drawerLoading || !drawerData ? (
              <div className="py-12 text-center text-slate-400">
                Loading event evidence and related telemetry correlation...
              </div>
            ) : (
              <>
                {/* Normalized Summary Grid */}
                <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 soc-panel p-3.5">
                  <div>
                    <div className="text-[10px] uppercase text-slate-400">Timestamp</div>
                    <div className="font-mono text-slate-100 mt-0.5">
                      {formatTimestamp(drawerData.event.timestamp)}
                    </div>
                  </div>
                  <div>
                    <div className="text-[10px] uppercase text-slate-400">Category / Type</div>
                    <div className="text-cyan-300 font-medium mt-0.5">
                      {drawerData.event.event_category} / {drawerData.event.event_type}
                    </div>
                  </div>
                  <div>
                    <div className="text-[10px] uppercase text-slate-400">Severity & Status</div>
                    <div className="flex items-center gap-2 mt-0.5">
                      <SeverityBadge severity={drawerData.event.severity} />
                      <span className="font-mono text-slate-200">{drawerData.event.status}</span>
                    </div>
                  </div>
                  <div>
                    <div className="text-[10px] uppercase text-slate-400">Source IP</div>
                    <div className="font-mono text-white mt-0.5 flex items-center gap-2">
                      {drawerData.event.source_ip}
                      <button
                        onClick={() =>
                          navigate(
                            `/threat-intelligence?ip=${encodeURIComponent(
                              drawerData.event.source_ip
                            )}`
                          )
                        }
                        className="text-[10px] text-cyan-400 hover:underline"
                      >
                        [IOC Lookup]
                      </button>
                    </div>
                  </div>
                  <div>
                    <div className="text-[10px] uppercase text-slate-400">Destination</div>
                    <div className="font-mono text-slate-200 mt-0.5">
                      {drawerData.event.destination_ip || '—'}
                      {drawerData.event.destination_port
                        ? `:${drawerData.event.destination_port}`
                        : ''}
                    </div>
                  </div>
                  <div>
                    <div className="text-[10px] uppercase text-slate-400">User & Host</div>
                    <div className="text-slate-200 mt-0.5">
                      {drawerData.event.username || '—'} @ {drawerData.event.hostname || '—'}
                    </div>
                  </div>
                </div>

                {/* Raw Log Evidence */}
                <div className="space-y-1.5">
                  <div className="flex items-center gap-1.5 font-semibold text-slate-200">
                    <FileText className="w-4 h-4 text-cyan-400" />
                    <span>Raw Event Log Evidence</span>
                  </div>
                  <pre className="p-3 rounded bg-[#090d16] border border-[#1e2c45] font-mono text-[11px] text-emerald-300 whitespace-pre-wrap break-all">
                    {drawerData.event.raw_log}
                  </pre>
                </div>

                {/* JSON Metadata Viewer */}
                <div className="space-y-1.5">
                  <div className="flex items-center gap-1.5 font-semibold text-slate-200">
                    <Code2 className="w-4 h-4 text-blue-400" />
                    <span>Normalized JSON Metadata</span>
                  </div>
                  <pre className="p-3 rounded bg-[#090d16] border border-[#1e2c45] font-mono text-[11px] text-slate-200 overflow-x-auto">
                    {JSON.stringify(drawerData.event.metadata, null, 2)}
                  </pre>
                </div>

                {/* Linked Alerts */}
                {drawerData.linked_alerts.length > 0 && (
                  <div className="space-y-2">
                    <div className="font-semibold text-slate-200">
                      Associated Detection Alerts ({drawerData.linked_alerts.length})
                    </div>
                    <div className="space-y-1.5">
                      {drawerData.linked_alerts.map((a) => (
                        <div
                          key={a.id}
                          onClick={() => navigate(`/alerts?alertId=${a.id}`)}
                          className="p-2.5 rounded bg-[#151f32] border border-[#243554] hover:border-cyan-500/40 cursor-pointer flex items-center justify-between"
                        >
                          <div>
                            <span className="font-mono text-cyan-400 mr-2">{a.alert_id}</span>
                            <span className="text-white font-medium">{a.title}</span>
                          </div>
                          <SeverityBadge severity={a.severity} />
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Related Event Correlation */}
                <div className="space-y-2">
                  <div className="flex items-center gap-1.5 font-semibold text-slate-200">
                    <GitBranch className="w-4 h-4 text-cyan-400" />
                    <span>
                      Correlated Events (±15m Same Source IP or Username) (
                      {drawerData.related_events.length})
                    </span>
                  </div>
                  {drawerData.related_events.length === 0 ? (
                    <div className="p-3 rounded bg-[#0f1623] border border-[#1e2c45] text-slate-400">
                      No other correlated events within the ±15 minute window.
                    </div>
                  ) : (
                    <div className="space-y-1.5 max-h-60 overflow-y-auto">
                      {drawerData.related_events.map((rel) => (
                        <div
                          key={rel.id}
                          onClick={() => openEventDrawer(rel.id)}
                          className="p-2 rounded bg-[#0f1623] border border-[#1e2c45] hover:border-cyan-500/40 cursor-pointer flex items-center justify-between"
                        >
                          <div>
                            <div className="font-mono text-[11px] text-cyan-300">
                              {rel.event_id} • {formatTimestamp(rel.timestamp)}
                            </div>
                            <div className="text-slate-200">
                              {rel.event_category}: {rel.event_type} ({rel.status}) —{' '}
                              {rel.username || rel.source_ip}
                            </div>
                          </div>
                          <SeverityBadge severity={rel.severity} />
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </>
            )}
          </div>
        </div>
      )}

      {/* Custom Event Ingestion Modal */}
      {ingestModalOpen && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
          <div className="soc-panel w-full max-w-lg p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-[#1e2c45] pb-3">
              <h3 className="text-sm font-semibold text-white">
                Ingest Security Event via REST Pipeline (/api/events)
              </h3>
              <button
                onClick={() => setIngestModalOpen(false)}
                className="text-slate-400 hover:text-white"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleIngestSubmit} className="space-y-3 text-xs">
              {ingestResultMsg && (
                <div className="p-2.5 rounded bg-cyan-500/15 border border-cyan-500/40 text-cyan-200">
                  {ingestResultMsg}
                </div>
              )}
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-400 mb-1">Source IP</label>
                  <input
                    type="text"
                    value={customEventForm.source_ip}
                    onChange={(e) =>
                      setCustomEventForm({ ...customEventForm, source_ip: e.target.value })
                    }
                    className="w-full bg-[#090d16] border border-[#1e2c45] rounded px-2.5 py-1.5 font-mono text-white"
                    required
                  />
                </div>
                <div>
                  <label className="block text-slate-400 mb-1">Destination IP</label>
                  <input
                    type="text"
                    value={customEventForm.destination_ip}
                    onChange={(e) =>
                      setCustomEventForm({ ...customEventForm, destination_ip: e.target.value })
                    }
                    className="w-full bg-[#090d16] border border-[#1e2c45] rounded px-2.5 py-1.5 font-mono text-white"
                  />
                </div>
                <div>
                  <label className="block text-slate-400 mb-1">Category</label>
                  <select
                    value={customEventForm.event_category}
                    onChange={(e) =>
                      setCustomEventForm({ ...customEventForm, event_category: e.target.value })
                    }
                    className="w-full bg-[#090d16] border border-[#1e2c45] rounded px-2.5 py-1.5 text-white"
                  >
                    <option value="Authentication">Authentication</option>
                    <option value="Authorization">Authorization</option>
                    <option value="Network">Network</option>
                    <option value="Endpoint">Endpoint</option>
                    <option value="System">System</option>
                    <option value="Application">Application</option>
                  </select>
                </div>
                <div>
                  <label className="block text-slate-400 mb-1">Severity</label>
                  <select
                    value={customEventForm.severity}
                    onChange={(e) =>
                      setCustomEventForm({ ...customEventForm, severity: e.target.value })
                    }
                    className="w-full bg-[#090d16] border border-[#1e2c45] rounded px-2.5 py-1.5 text-white"
                  >
                    <option value="low">Low</option>
                    <option value="medium">Medium</option>
                    <option value="high">High</option>
                    <option value="critical">Critical</option>
                  </select>
                </div>
                <div>
                  <label className="block text-slate-400 mb-1">Username</label>
                  <input
                    type="text"
                    value={customEventForm.username}
                    onChange={(e) =>
                      setCustomEventForm({ ...customEventForm, username: e.target.value })
                    }
                    className="w-full bg-[#090d16] border border-[#1e2c45] rounded px-2.5 py-1.5 text-white"
                  />
                </div>
                <div>
                  <label className="block text-slate-400 mb-1">Event Type</label>
                  <input
                    type="text"
                    value={customEventForm.event_type}
                    onChange={(e) =>
                      setCustomEventForm({ ...customEventForm, event_type: e.target.value })
                    }
                    className="w-full bg-[#090d16] border border-[#1e2c45] rounded px-2.5 py-1.5 text-white"
                    required
                  />
                </div>
              </div>
              <div>
                <label className="block text-slate-400 mb-1">Raw Log Evidence</label>
                <textarea
                  rows={3}
                  value={customEventForm.raw_log}
                  onChange={(e) =>
                    setCustomEventForm({ ...customEventForm, raw_log: e.target.value })
                  }
                  className="w-full bg-[#090d16] border border-[#1e2c45] rounded p-2 font-mono text-white"
                  required
                />
              </div>
              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setIngestModalOpen(false)}
                  className="px-3 py-1.5 rounded border border-[#1e2c45] text-slate-300"
                >
                  Close
                </button>
                <button
                  type="submit"
                  className="px-4 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-white font-medium"
                >
                  Ingest & Evaluate Rules
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

