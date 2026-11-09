import React, { useCallback, useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import {
  AlertTriangle,
  CheckCircle2,
  Globe,
  KeyRound,
  Plus,
  Search,
  ShieldAlert,
  Trash2,
  X,
} from 'lucide-react';
import { api } from '../services/api';
import { ThreatIndicator } from '../types';
import { SeverityBadge } from '../components/SeverityBadge';
import { formatTimestamp } from '../utils/formatters';

export const ThreatIntelligencePage: React.FC = () => {
  const [searchParams] = useSearchParams();

  // IP Reputation Lookup State
  const [lookupIp, setLookupIp] = useState(
    searchParams.get('ip') || '185.220.101.42'
  );
  const [lookupResult, setLookupResult] = useState<any | null>(null);
  const [lookupLoading, setLookupLoading] = useState(false);
  const [lookupError, setLookupError] = useState<string | null>(null);

  // IOC List & Suspicious IP Tracking State
  const [indicators, setIndicators] = useState<ThreatIndicator[]>([]);
  const [suspiciousIps, setSuspiciousIps] = useState<any[]>([]);
  const [iocSearch, setIocSearch] = useState('');
  const [iocThreatFilter, setIocThreatFilter] = useState('all');
  const [providerStatus, setProviderStatus] = useState<any | null>(null);

  // Add IOC Modal
  const [addIocOpen, setAddIocOpen] = useState(false);
  const [newIocForm, setNewIocForm] = useState({
    indicator_type: 'ip',
    indicator_value: '',
    threat_type: 'c2',
    severity: 'critical',
    confidence: 90,
    source: 'Internal SOC Investigation',
    description: '',
    tags: 'c2,outbound-anomaly',
  });

  // External Provider Config Modal
  const [providerModalOpen, setProviderModalOpen] = useState(false);
  const [providerKeys, setProviderKeys] = useState({
    abuseipdb_api_key: '',
    virustotal_api_key: '',
    otx_api_key: '',
    enable_external_lookup: true,
  });

  const loadIndicatorsAndProviders = useCallback(async () => {
    const [iocList, prov, trackedIps] = await Promise.all([
      api.listThreatIndicators({
        search: iocSearch.trim() || undefined,
        threat_type: iocThreatFilter,
      }),
      api.getThreatIntelProviders(),
      api.listSuspiciousIps({ limit: 25 }).catch(() => []),
    ]);
    setIndicators(iocList);
    setProviderStatus(prov);
    setSuspiciousIps(
      Array.isArray(trackedIps) ? trackedIps : (trackedIps as any)?.items || []
    );
  }, [iocSearch, iocThreatFilter]);

  const executeIpLookup = useCallback(async (ipToQuery: string) => {
    if (!ipToQuery.trim()) return;
    setLookupLoading(true);
    setLookupError(null);
    try {
      const res = await api.lookupIpIntelligence(ipToQuery.trim());
      setLookupResult(res);
    } catch (err: any) {
      setLookupError(err.message || 'Lookup failed');
      setLookupResult(null);
    } finally {
      setLookupLoading(false);
    }
  }, []);

  useEffect(() => {
    loadIndicatorsAndProviders();
  }, [loadIndicatorsAndProviders]);

  useEffect(() => {
    executeIpLookup(lookupIp);
  }, []);

  const handleAddIocSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    await api.createThreatIndicator({
      ...newIocForm,
      confidence: Number(newIocForm.confidence),
      tags: newIocForm.tags
        .split(',')
        .map((t) => t.trim())
        .filter(Boolean),
    });
    setAddIocOpen(false);
    setNewIocForm({
      ...newIocForm,
      indicator_value: '',
      description: '',
    });
    await loadIndicatorsAndProviders();
  };

  const handleDeleteIoc = async (id: number) => {
    await api.deleteThreatIndicator(id);
    await loadIndicatorsAndProviders();
  };

  const handleToggleIocActive = async (ioc: ThreatIndicator) => {
    await api.updateThreatIndicator(ioc.id, { is_active: !ioc.is_active });
    await loadIndicatorsAndProviders();
  };

  const handlePromoteTrackedIpToIoc = async (tracked: any) => {
    await api.createThreatIndicator({
      indicator_type: 'ip',
      indicator_value: tracked.ip,
      threat_type:
        tracked.failed_logins >= 3
          ? 'brute_force'
          : tracked.alert_count > 0
          ? 'suspicious_actor'
          : 'scanner',
      severity: tracked.highest_alert_severity || 'high',
      confidence: 85,
      source: 'SIEM Suspicious IP Tracker',
      description: `Promoted from SIEM telemetry (${tracked.total_events} events, ${tracked.alert_count} alerts, rules: ${(tracked.triggered_rules || []).join(', ') || 'telemetry'}).`,
      tags: ['siem-tracked', ...(tracked.triggered_rules || [])],
      is_active: true,
    });
    await loadIndicatorsAndProviders();
    await executeIpLookup(tracked.ip);
  };

  const handleSaveProviders = async (e: React.FormEvent) => {
    e.preventDefault();
    const res = await api.updateThreatIntelProviders(providerKeys);
    setProviderStatus(res);
    setProviderModalOpen(false);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-white">
            Threat Intelligence & Indicator of Compromise (IOC) Repository
          </h1>
          <p className="text-xs text-slate-400">
            Evidence-based IP reputation lookup, suspicious IP tracking, local IOC feed management, and external provider abstraction
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setProviderModalOpen(true)}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-[#151f32] hover:bg-[#1e2c45] border border-[#243554] text-slate-200 text-xs"
          >
            <KeyRound className="w-3.5 h-3.5 text-cyan-400" />
            Configure External Providers
          </button>
          <button
            onClick={() => setAddIocOpen(true)}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-medium"
          >
            <Plus className="w-3.5 h-3.5" />
            Add Threat Indicator (IOC)
          </button>
        </div>
      </div>

      {/* IP Reputation & Telemetry Correlation Lookup */}
      <div className="soc-panel p-5 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h2 className="text-sm font-semibold text-white flex items-center gap-2">
              <Globe className="w-4 h-4 text-cyan-400" />
              IP Reputation & SIEM Telemetry Correlation Lookup
            </h2>
            <p className="text-[11px] text-slate-400">
              Queries verified local IOC records, internal PostgreSQL SIEM events, and configured external providers (never fabricates unverified scores)
            </p>
          </div>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              executeIpLookup(lookupIp);
            }}
            className="flex items-center gap-2"
          >
            <input
              type="text"
              value={lookupIp}
              onChange={(e) => setLookupIp(e.target.value)}
              placeholder="Enter IPv4 or IPv6 (e.g. 185.220.101.42)"
              className="w-64 bg-[#090d16] border border-[#1e2c45] rounded px-3 py-1.5 text-xs font-mono text-white"
            />
            <button
              type="submit"
              disabled={lookupLoading}
              className="px-4 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-medium"
            >
              {lookupLoading ? 'Querying...' : 'Lookup IP'}
            </button>
          </form>
        </div>

        {/* Quick Lookup Sample Pills */}
        <div className="flex flex-wrap items-center gap-2 text-[11px]">
          <span className="text-slate-400">Quick test IPs:</span>
          {['185.220.101.42', '91.240.118.172', '203.0.113.250', '10.10.20.14', '8.8.8.8'].map(
            (sampleIp) => (
              <button
                key={sampleIp}
                onClick={() => {
                  setLookupIp(sampleIp);
                  executeIpLookup(sampleIp);
                }}
                className="px-2 py-0.5 rounded bg-[#151f32] hover:bg-[#1e2c45] border border-[#243554] font-mono text-cyan-300"
              >
                {sampleIp}
              </button>
            )
          )}
        </div>

        {lookupError && (
          <div className="p-3 rounded bg-red-500/15 border border-red-500/40 text-red-300 text-xs">
            {lookupError}
          </div>
        )}

        {lookupResult && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 text-xs pt-1">
            {/* Verdict & Local IOC Card */}
            <div className="p-4 rounded bg-[#090d16] border border-[#1e2c45] space-y-2.5">
              <div className="flex items-center justify-between">
                <span className="font-mono text-sm font-bold text-white">
                  {lookupResult.ip}
                </span>
                {lookupResult.verdict === 'confirmed_ioc_match' ||
                lookupResult.verdict === 'external_intel_match' ? (
                  <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-red-500/15 text-red-400 border border-red-500/40 font-semibold">
                    <ShieldAlert className="w-3.5 h-3.5" />
                    CONFIRMED IOC
                  </span>
                ) : (
                  <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-slate-700/40 text-slate-300 border border-slate-600 font-medium">
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                    NO IOC MATCH
                  </span>
                )}
              </div>

              <p className="text-slate-300 leading-relaxed">
                {lookupResult.verdict_summary}
              </p>

              <div className="grid grid-cols-2 gap-2 pt-2 border-t border-[#1e2c45] text-[11px]">
                <div>
                  <span className="text-slate-400">Scope: </span>
                  <span className="font-mono text-slate-200">
                    {lookupResult.network_classification.is_private
                      ? 'RFC1918 Private'
                      : 'Global Public'}
                  </span>
                </div>
                <div>
                  <span className="text-slate-400">Verified Confidence: </span>
                  <span className="font-mono text-cyan-300">
                    {lookupResult.reputation_confidence !== null
                      ? `${lookupResult.reputation_confidence}%`
                      : 'N/A (Unverified)'}
                  </span>
                </div>
              </div>
            </div>

            {/* Internal SIEM Telemetry Activity */}
            <div className="p-4 rounded bg-[#090d16] border border-[#1e2c45] space-y-2">
              <div className="font-semibold text-white">
                Internal SIEM Telemetry Correlation
              </div>
              <div className="grid grid-cols-2 gap-2">
                <div className="p-2 rounded bg-[#151f32]">
                  <div className="text-[10px] text-slate-400">Events as Source</div>
                  <div className="text-base font-bold font-mono text-white">
                    {lookupResult.internal_telemetry.events_as_source}
                  </div>
                </div>
                <div className="p-2 rounded bg-[#151f32]">
                  <div className="text-[10px] text-slate-400">Failed Logins</div>
                  <div className="text-base font-bold font-mono text-orange-400">
                    {lookupResult.internal_telemetry.failed_authentications}
                  </div>
                </div>
              </div>
              <div className="text-[11px] text-slate-400 pt-1">
                Associated Alerts: {lookupResult.internal_telemetry.associated_alerts_count}
              </div>
            </div>

            {/* External Providers Status */}
            <div className="p-4 rounded bg-[#090d16] border border-[#1e2c45] space-y-2">
              <div className="font-semibold text-white">
                External Threat Intelligence Providers
              </div>
              <div className="space-y-2">
                {lookupResult.external_providers.map((ext: any) => (
                  <div
                    key={ext.provider}
                    className="p-2 rounded bg-[#151f32] border border-[#243554] space-y-0.5"
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-medium text-slate-200">{ext.provider}</span>
                      <span className="font-mono text-[10px] uppercase text-slate-400">
                        {ext.status}
                      </span>
                    </div>
                    <div className="text-[11px] text-slate-400">
                      {ext.message || `Score: ${ext.abuse_confidence_score ?? ext.malicious_votes ?? 0}`}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Suspicious IP Tracking Panel */}
      <div className="soc-panel overflow-hidden">
        <div className="p-4 border-b border-[#1e2c45] flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs">
          <div>
            <h2 className="text-sm font-semibold text-white flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-orange-400" />
              Suspicious IP Tracking ({suspiciousIps.length})
            </h2>
            <p className="text-[11px] text-slate-400">
              Real-time correlation of source/destination IPs observed in SIEM security events, triggered detection rules, and IOC feeds
            </p>
          </div>
          <span className="text-[11px] font-mono text-cyan-300">
            Evidence-Driven Telemetry Tracking
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="bg-[#0c121e] border-b border-[#1e2c45] text-slate-400 text-[11px] uppercase">
                <th className="py-2.5 px-3">Tracked IP</th>
                <th className="py-2.5 px-3">Tracking Classification</th>
                <th className="py-2.5 px-3">SIEM Events</th>
                <th className="py-2.5 px-3">Failed Logins</th>
                <th className="py-2.5 px-3">Alerts & Rules</th>
                <th className="py-2.5 px-3">IOC Status</th>
                <th className="py-2.5 px-3">Last Observed</th>
                <th className="py-2.5 px-3">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1e2c45]">
              {suspiciousIps.map((item) => (
                <tr key={item.ip} className="hover:bg-[#151f32]">
                  <td className="py-2.5 px-3 font-mono font-semibold text-cyan-400">
                    <button
                      onClick={() => {
                        setLookupIp(item.ip);
                        executeIpLookup(item.ip);
                      }}
                      className="hover:underline"
                    >
                      {item.ip}
                    </button>
                  </td>
                  <td className="py-2.5 px-3">
                    <span
                      className={`px-2 py-0.5 rounded font-mono text-[10px] uppercase ${
                        item.tracking_status === 'confirmed_ioc'
                          ? 'bg-red-500/15 text-red-300 border border-red-500/30'
                          : item.tracking_status === 'alert_source'
                          ? 'bg-orange-500/15 text-orange-300 border border-orange-500/30'
                          : 'bg-yellow-500/15 text-yellow-300 border border-yellow-500/30'
                      }`}
                    >
                      {item.tracking_status.replace(/_/g, ' ')}
                    </span>
                  </td>
                  <td className="py-2.5 px-3 font-mono text-white">{item.total_events}</td>
                  <td className="py-2.5 px-3 font-mono text-orange-300">{item.failed_logins}</td>
                  <td className="py-2.5 px-3">
                    <span className="font-mono text-white font-semibold mr-1.5">
                      {item.alert_count}
                    </span>
                    {item.triggered_rules?.length > 0 && (
                      <span className="font-mono text-[11px] text-cyan-300">
                        ({item.triggered_rules.join(', ')})
                      </span>
                    )}
                  </td>
                  <td className="py-2.5 px-3">
                    {item.is_active_ioc ? (
                      <span className="text-red-300 font-mono text-[11px]">
                        IOC ({item.ioc_threat_type} • {item.ioc_confidence}%)
                      </span>
                    ) : (
                      <span className="text-slate-400 text-[11px]">Untracked in IOC DB</span>
                    )}
                  </td>
                  <td className="py-2.5 px-3 font-mono text-[11px] text-slate-400">
                    {item.last_seen ? formatTimestamp(item.last_seen) : '—'}
                  </td>
                  <td className="py-2.5 px-3">
                    <div className="flex items-center gap-1.5">
                      <button
                        onClick={() => {
                          setLookupIp(item.ip);
                          executeIpLookup(item.ip);
                        }}
                        className="px-2 py-1 rounded bg-[#151f32] hover:bg-[#1e2c45] border border-[#243554] text-cyan-300 text-[11px]"
                      >
                        Inspect
                      </button>
                      {!item.is_active_ioc && (
                        <button
                          onClick={() => handlePromoteTrackedIpToIoc(item)}
                          className="px-2 py-1 rounded bg-cyan-600/20 hover:bg-cyan-600/30 border border-cyan-500/40 text-cyan-200 text-[11px]"
                        >
                          + Track IOC
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* IOC Management Table */}
      <div className="soc-panel overflow-hidden">
        <div className="p-4 border-b border-[#1e2c45] flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
          <div>
            <h2 className="text-sm font-semibold text-white">
              Indicators of Compromise (IOC) Database ({indicators.length})
            </h2>
            <p className="text-[11px] text-slate-400">
              Active indicators correlated automatically during event ingestion and rule evaluation
            </p>
          </div>
          <div className="flex items-center gap-2">
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-2" />
              <input
                type="text"
                value={iocSearch}
                onChange={(e) => setIocSearch(e.target.value)}
                placeholder="Search indicator value, tag, source..."
                className="bg-[#090d16] border border-[#1e2c45] rounded pl-8 pr-3 py-1 text-white"
              />
            </div>
            <select
              value={iocThreatFilter}
              onChange={(e) => setIocThreatFilter(e.target.value)}
              className="bg-[#090d16] border border-[#1e2c45] rounded px-2.5 py-1 text-white"
            >
              <option value="all">All Threat Types</option>
              <option value="brute_force">Brute Force</option>
              <option value="botnet">Botnet</option>
              <option value="c2">C2 Server</option>
              <option value="scanner">Scanner</option>
              <option value="suspicious_actor">Suspicious Actor</option>
            </select>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="bg-[#0c121e] border-b border-[#1e2c45] text-slate-400 text-[11px] uppercase">
                <th className="py-2.5 px-3">Indicator Value</th>
                <th className="py-2.5 px-3">Type</th>
                <th className="py-2.5 px-3">Threat Classification</th>
                <th className="py-2.5 px-3">Severity</th>
                <th className="py-2.5 px-3">Confidence</th>
                <th className="py-2.5 px-3">Source & Description</th>
                <th className="py-2.5 px-3">SIEM Hits</th>
                <th className="py-2.5 px-3">Last Seen</th>
                <th className="py-2.5 px-3">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1e2c45]">
              {indicators.map((ioc) => (
                <tr key={ioc.id} className="hover:bg-[#151f32]">
                  <td className="py-2.5 px-3 font-mono font-semibold text-cyan-400">
                    <button
                      onClick={() => {
                        setLookupIp(ioc.indicator_value);
                        executeIpLookup(ioc.indicator_value);
                      }}
                      className="hover:underline"
                    >
                      {ioc.indicator_value}
                    </button>
                  </td>
                  <td className="py-2.5 px-3 uppercase font-mono text-slate-300">
                    {ioc.indicator_type}
                  </td>
                  <td className="py-2.5 px-3 font-mono text-orange-300">
                    {ioc.threat_type}
                  </td>
                  <td className="py-2.5 px-3">
                    <SeverityBadge severity={ioc.severity} />
                  </td>
                  <td className="py-2.5 px-3 font-mono text-slate-200">
                    {ioc.confidence}%
                  </td>
                  <td className="py-2.5 px-3">
                    <div className="font-medium text-slate-200">{ioc.source}</div>
                    <div className="text-[11px] text-slate-400">{ioc.description}</div>
                  </td>
                  <td className="py-2.5 px-3 font-mono text-white">{ioc.hit_count}</td>
                  <td className="py-2.5 px-3 font-mono text-[11px] text-slate-400">
                    {formatTimestamp(ioc.last_seen)}
                  </td>
                  <td className="py-2.5 px-3">
                    <div className="flex items-center gap-1.5">
                      <button
                        onClick={() => handleToggleIocActive(ioc)}
                        className={`px-2 py-0.5 rounded text-[10px] font-mono uppercase border ${
                          ioc.is_active
                            ? 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
                            : 'bg-slate-700/30 text-slate-400 border-slate-600'
                        }`}
                        title="Toggle Active Status"
                      >
                        {ioc.is_active ? 'Active' : 'Inactive'}
                      </button>
                      <button
                        onClick={() => handleDeleteIoc(ioc.id)}
                        className="p-1 rounded hover:bg-red-500/20 text-slate-400 hover:text-red-400"
                        title="Delete IOC"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Add IOC Modal */}
      {addIocOpen && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
          <div className="soc-panel w-full max-w-md p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-[#1e2c45] pb-3">
              <h3 className="text-sm font-semibold text-white">Add Threat Indicator (IOC)</h3>
              <button
                onClick={() => setAddIocOpen(false)}
                className="text-slate-400 hover:text-white"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
            <form onSubmit={handleAddIocSubmit} className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-400 mb-1">Indicator Value (IP / Domain)</label>
                <input
                  type="text"
                  value={newIocForm.indicator_value}
                  onChange={(e) =>
                    setNewIocForm({ ...newIocForm, indicator_value: e.target.value })
                  }
                  placeholder="e.g. 192.0.2.99"
                  className="w-full bg-[#090d16] border border-[#1e2c45] rounded px-3 py-1.5 font-mono text-white"
                  required
                />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-400 mb-1">Threat Classification</label>
                  <select
                    value={newIocForm.threat_type}
                    onChange={(e) =>
                      setNewIocForm({ ...newIocForm, threat_type: e.target.value })
                    }
                    className="w-full bg-[#090d16] border border-[#1e2c45] rounded px-2.5 py-1.5 text-white"
                  >
                    <option value="c2">c2</option>
                    <option value="brute_force">brute_force</option>
                    <option value="botnet">botnet</option>
                    <option value="scanner">scanner</option>
                    <option value="suspicious_actor">suspicious_actor</option>
                  </select>
                </div>
                <div>
                  <label className="block text-slate-400 mb-1">Severity</label>
                  <select
                    value={newIocForm.severity}
                    onChange={(e) =>
                      setNewIocForm({ ...newIocForm, severity: e.target.value })
                    }
                    className="w-full bg-[#090d16] border border-[#1e2c45] rounded px-2.5 py-1.5 text-white"
                  >
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                  </select>
                </div>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-400 mb-1">Confidence (0-100%)</label>
                  <input
                    type="number"
                    min={0}
                    max={100}
                    value={newIocForm.confidence}
                    onChange={(e) =>
                      setNewIocForm({ ...newIocForm, confidence: Number(e.target.value) })
                    }
                    className="w-full bg-[#090d16] border border-[#1e2c45] rounded px-2.5 py-1.5 font-mono text-white"
                  />
                </div>
                <div>
                  <label className="block text-slate-400 mb-1">Source</label>
                  <input
                    type="text"
                    value={newIocForm.source}
                    onChange={(e) =>
                      setNewIocForm({ ...newIocForm, source: e.target.value })
                    }
                    className="w-full bg-[#090d16] border border-[#1e2c45] rounded px-2.5 py-1.5 text-white"
                  />
                </div>
              </div>
              <div>
                <label className="block text-slate-400 mb-1">Description</label>
                <textarea
                  rows={2}
                  value={newIocForm.description}
                  onChange={(e) =>
                    setNewIocForm({ ...newIocForm, description: e.target.value })
                  }
                  className="w-full bg-[#090d16] border border-[#1e2c45] rounded p-2 text-white"
                />
              </div>
              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setAddIocOpen(false)}
                  className="px-3 py-1.5 rounded border border-[#1e2c45] text-slate-300"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-white font-medium"
                >
                  Save IOC
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* External Provider Configuration Modal */}
      {providerModalOpen && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
          <div className="soc-panel w-full max-w-md p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-[#1e2c45] pb-3">
              <h3 className="text-sm font-semibold text-white">
                External Threat Intelligence Provider Configuration
              </h3>
              <button
                onClick={() => setProviderModalOpen(false)}
                className="text-slate-400 hover:text-white"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
            <form onSubmit={handleSaveProviders} className="space-y-3 text-xs">
              <p className="text-slate-400 text-[11px]">
                Configure optional API keys for AbuseIPDB or VirusTotal. When blank, ThreatLens relies strictly on the local PostgreSQL IOC database without fabricating external reputation scores.
              </p>
              <div>
                <label className="block text-slate-300 mb-1">
                  AbuseIPDB API v2 Key (<code className="text-cyan-300">ABUSEIPDB_API_KEY</code>)
                </label>
                <input
                  type="password"
                  value={providerKeys.abuseipdb_api_key}
                  onChange={(e) =>
                    setProviderKeys({ ...providerKeys, abuseipdb_api_key: e.target.value })
                  }
                  placeholder="Optional AbuseIPDB key..."
                  className="w-full bg-[#090d16] border border-[#1e2c45] rounded px-3 py-1.5 text-white"
                />
              </div>
              <div>
                <label className="block text-slate-300 mb-1">
                  VirusTotal API v3 Key (<code className="text-cyan-300">VIRUSTOTAL_API_KEY</code>)
                </label>
                <input
                  type="password"
                  value={providerKeys.virustotal_api_key}
                  onChange={(e) =>
                    setProviderKeys({ ...providerKeys, virustotal_api_key: e.target.value })
                  }
                  placeholder="Optional VirusTotal key..."
                  className="w-full bg-[#090d16] border border-[#1e2c45] rounded px-3 py-1.5 text-white"
                />
              </div>
              <div>
                <label className="block text-slate-300 mb-1">
                  AlienVault OTX Key (<code className="text-cyan-300">OTX_API_KEY</code>)
                </label>
                <input
                  type="password"
                  value={providerKeys.otx_api_key}
                  onChange={(e) =>
                    setProviderKeys({ ...providerKeys, otx_api_key: e.target.value })
                  }
                  placeholder="Optional AlienVault OTX key..."
                  className="w-full bg-[#090d16] border border-[#1e2c45] rounded px-3 py-1.5 text-white"
                />
              </div>
              <label className="flex items-center gap-2 text-slate-300 pt-1">
                <input
                  type="checkbox"
                  checked={providerKeys.enable_external_lookup}
                  onChange={(e) =>
                    setProviderKeys({
                      ...providerKeys,
                      enable_external_lookup: e.target.checked,
                    })
                  }
                />
                <span>Enable external threat intelligence API lookups when keys are configured</span>
              </label>
              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setProviderModalOpen(false)}
                  className="px-3 py-1.5 rounded border border-[#1e2c45] text-slate-300"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-white font-medium"
                >
                  Save Provider Settings
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

