import React, { useEffect, useState } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  Copy,
  Globe,
  Loader2,
  RefreshCw,
  Search,
  ShieldAlert,
  ShieldCheck,
  X,
} from 'lucide-react';
import { api } from '../services/api';
import { SeverityBadge } from './SeverityBadge';
import { formatTimestamp } from '../utils/formatters';

interface ThreatIntelModalProps {
  isOpen: boolean;
  onClose: () => void;
  initialIp?: string;
  onAttachEvidenceNote?: (note: string) => Promise<void> | void;
}

export const ThreatIntelModal: React.FC<ThreatIntelModalProps> = ({
  isOpen,
  onClose,
  initialIp = '',
  onAttachEvidenceNote,
}) => {
  const [ipQuery, setIpQuery] = useState(initialIp);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<any | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [attached, setAttached] = useState(false);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (isOpen) {
      const target = initialIp.trim() || '185.220.101.42';
      setIpQuery(target);
      executeLookup(target);
      setAttached(false);
      setCopied(false);
    }
  }, [isOpen, initialIp]);

  const executeLookup = async (ipToQuery: string) => {
    const cleanIp = ipToQuery.trim();
    if (!cleanIp) return;
    setLoading(true);
    setError(null);
    try {
      const data = await api.lookupIpIntelligence(cleanIp);
      setResult(data);
    } catch (err: any) {
      setError(err.message || 'Threat intelligence lookup failed');
      setResult(null);
    } finally {
      setLoading(false);
    }
  };

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    executeLookup(ipQuery);
  };

  const handleCopySummary = () => {
    if (!result) return;
    const summary = `[ThreatLens TI] IP: ${result.ip} | Score: ${result.reputation_score}/100 | Severity: ${result.severity?.toUpperCase()} | Verdict: ${result.verdict} | Indicators: ${result.known_malicious_indicators?.length || 0}`;
    navigator.clipboard.writeText(summary);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleAttach = async () => {
    if (!result || !onAttachEvidenceNote) return;
    const note = `Threat Intelligence Enrichment for ${result.ip}: Threat Score ${result.reputation_score}/100 (${result.severity?.toUpperCase()}), Verdict: ${result.verdict}. Country: ${result.country || 'Unknown'}, ISP: ${result.isp || 'Unknown'}. Provider detections: AbuseIPDB=${result.providers?.abuseipdb?.verdict || 'N/A'}, VirusTotal=${result.providers?.virustotal?.verdict || 'N/A'}.`;
    await onAttachEvidenceNote(note);
    setAttached(true);
    setTimeout(() => setAttached(false), 3000);
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm animate-fade-in">
      <div className="soc-panel w-full max-w-2xl max-h-[90vh] flex flex-col bg-[#0b101b] border border-[#243554] shadow-2xl rounded-lg overflow-hidden">
        {/* Modal Header */}
        <div className="flex items-center justify-between p-4 border-b border-[#1e2c45] bg-[#0f1623]">
          <div className="flex items-center gap-2">
            <Globe className="w-5 h-5 text-cyan-400" />
            <div>
              <h2 className="text-sm font-bold text-white">Threat Intelligence Enrichment</h2>
              <p className="text-[11px] text-slate-400">
                On-demand IP reputation, IOC correlation, and external threat intel feeds
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded text-slate-400 hover:text-white hover:bg-[#151f32]"
            aria-label="Close modal"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Search Bar */}
        <div className="p-4 border-b border-[#1e2c45] bg-[#121927]">
          <form onSubmit={handleSearchSubmit} className="flex gap-2">
            <div className="relative flex-1">
              <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-slate-400" />
              <input
                type="text"
                value={ipQuery}
                onChange={(e) => setIpQuery(e.target.value)}
                placeholder="Enter IPv4 address (e.g. 185.220.101.42, 192.168.1.50)..."
                className="w-full pl-9 pr-3 py-1.5 bg-[#090d16] border border-[#1e2c45] rounded text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
              />
            </div>
            <button
              type="submit"
              disabled={loading || !ipQuery.trim()}
              className="px-3 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 disabled:opacity-40 text-white text-xs font-medium flex items-center gap-1.5"
            >
              {loading ? (
                <>
                  <Loader2 className="w-3.5 h-3.5 animate-spin" />
                  Checking...
                </>
              ) : (
                <>
                  <Search className="w-3.5 h-3.5" />
                  Lookup IP
                </>
              )}
            </button>
          </form>
        </div>

        {/* Modal Body */}
        <div className="flex-1 overflow-y-auto p-4 space-y-4 text-xs">
          {loading && !result && (
            <div className="py-12 text-center text-slate-400 flex flex-col items-center justify-center gap-2">
              <Loader2 className="w-6 h-6 animate-spin text-cyan-400" />
              <span>Querying internal IOC repository and threat intelligence feeds...</span>
            </div>
          )}

          {error && (
            <div className="p-3 rounded bg-red-500/10 border border-red-500/30 text-red-300 flex items-start gap-2">
              <AlertTriangle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
              <div>
                <span className="font-semibold">Lookup Error:</span> {error}
              </div>
            </div>
          )}

          {result && (
            <div className="space-y-4">
              {/* Score & Verdict Card */}
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                <div className="p-3 rounded bg-[#151f32] border border-[#243554] flex flex-col justify-between">
                  <div className="text-[10px] uppercase text-slate-400">Reputation Score</div>
                  <div className="flex items-baseline gap-2 mt-1">
                    <span
                      className={`text-2xl font-black font-mono ${
                        result.reputation_score >= 70
                          ? 'text-red-400'
                          : result.reputation_score >= 40
                          ? 'text-yellow-400'
                          : 'text-emerald-400'
                      }`}
                    >
                      {result.reputation_score}
                    </span>
                    <span className="text-slate-400 text-xs">/ 100</span>
                  </div>
                  <div className="text-[10px] text-slate-400 mt-1">
                    {result.reputation_score >= 70
                      ? 'High Malicious Risk'
                      : result.reputation_score >= 40
                      ? 'Suspicious Indicator'
                      : 'Clean / Low Risk'}
                  </div>
                </div>

                <div className="p-3 rounded bg-[#151f32] border border-[#243554] flex flex-col justify-between">
                  <div className="text-[10px] uppercase text-slate-400">Threat Verdict</div>
                  <div className="mt-1">
                    <SeverityBadge severity={result.severity || 'low'} />
                  </div>
                  <div className="text-xs text-white font-semibold mt-1 capitalize">
                    {result.verdict || 'Clean'}
                  </div>
                </div>

                <div className="p-3 rounded bg-[#151f32] border border-[#243554] flex flex-col justify-between">
                  <div className="text-[10px] uppercase text-slate-400">IOC Matches</div>
                  <div className="text-2xl font-black font-mono text-cyan-400 mt-1">
                    {result.known_malicious_indicators?.length || 0}
                  </div>
                  <div className="text-[10px] text-slate-400 mt-1">
                    Internal Threat Indicators
                  </div>
                </div>
              </div>

              {/* Network & Geolocation Metadata */}
              <div className="p-3 rounded bg-[#151f32] border border-[#243554] space-y-2">
                <div className="text-[10px] uppercase font-bold text-slate-400 tracking-wider">
                  Network & Geolocation Details
                </div>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs">
                  <div>
                    <span className="text-slate-400 block text-[10px]">Queried IP</span>
                    <span className="font-mono text-white font-medium">{result.ip}</span>
                  </div>
                  <div>
                    <span className="text-slate-400 block text-[10px]">Country</span>
                    <span className="text-white">{result.country || 'Unknown'}</span>
                  </div>
                  <div>
                    <span className="text-slate-400 block text-[10px]">ISP / ASN</span>
                    <span className="text-white truncate block" title={result.isp || 'N/A'}>
                      {result.isp || 'N/A'}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-400 block text-[10px]">Last Analyzed</span>
                    <span className="text-slate-300">
                      {result.timestamp ? formatTimestamp(result.timestamp) : 'Just now'}
                    </span>
                  </div>
                </div>
              </div>

              {/* Intelligence Provider Breakdown */}
              {result.providers && (
                <div className="p-3 rounded bg-[#151f32] border border-[#243554] space-y-2">
                  <div className="text-[10px] uppercase font-bold text-slate-400 tracking-wider">
                    Threat Intelligence Provider Status
                  </div>
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                    {Object.entries(result.providers).map(([provName, provData]: [string, any]) => (
                      <div
                        key={provName}
                        className="p-2 rounded bg-[#090d16] border border-[#1e2c45] space-y-1"
                      >
                        <div className="flex items-center justify-between text-[11px] font-semibold text-white capitalize">
                          <span>{provName}</span>
                          {provData?.verdict === 'malicious' ? (
                            <span className="text-red-400 font-mono text-[10px]">Malicious</span>
                          ) : provData?.verdict === 'suspicious' ? (
                            <span className="text-yellow-400 font-mono text-[10px]">Suspicious</span>
                          ) : (
                            <span className="text-emerald-400 font-mono text-[10px]">Clean</span>
                          )}
                        </div>
                        <div className="text-[10px] text-slate-400 truncate">
                          {provData?.details || 'Analyzed against latest signature database'}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Matched Known IOCs */}
              {result.known_malicious_indicators && result.known_malicious_indicators.length > 0 && (
                <div className="p-3 rounded bg-red-500/10 border border-red-500/30 space-y-2">
                  <div className="flex items-center gap-1.5 text-red-300 font-bold text-xs">
                    <ShieldAlert className="w-3.5 h-3.5" />
                    Matched Malicious IOC Indicator(s) in Threat Database
                  </div>
                  <div className="space-y-1.5">
                    {result.known_malicious_indicators.map((ioc: any, idx: number) => (
                      <div
                        key={idx}
                        className="p-2 rounded bg-[#090d16]/80 border border-red-500/30 flex items-center justify-between text-xs"
                      >
                        <div>
                          <div className="font-mono text-red-400 font-bold">{ioc.indicator_value}</div>
                          <div className="text-[10px] text-slate-300">{ioc.description || 'Active Threat Indicator'}</div>
                        </div>
                        <div className="flex items-center gap-1.5">
                          <span className="px-1.5 py-0.5 rounded bg-red-500/20 text-red-300 text-[10px] font-mono uppercase">
                            {ioc.threat_type}
                          </span>
                          <span className="text-[10px] text-slate-400 font-mono">
                            Conf: {ioc.confidence}%
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Modal Footer Actions */}
        <div className="p-3 border-t border-[#1e2c45] bg-[#0f1623] flex flex-wrap items-center justify-between gap-2 text-xs">
          <div className="text-slate-400 text-[11px]">
            {attached && (
              <span className="text-emerald-400 flex items-center gap-1">
                <CheckCircle2 className="w-3.5 h-3.5" /> Added to investigation notes!
              </span>
            )}
            {copied && (
              <span className="text-cyan-400 flex items-center gap-1">
                <CheckCircle2 className="w-3.5 h-3.5" /> Intelligence summary copied!
              </span>
            )}
          </div>
          <div className="flex items-center gap-2">
            {result && (
              <button
                type="button"
                onClick={handleCopySummary}
                className="px-2.5 py-1.5 rounded bg-[#151f32] hover:bg-[#1e2c45] border border-[#243554] text-slate-200 inline-flex items-center gap-1.5"
              >
                <Copy className="w-3.5 h-3.5" />
                Copy Verdict
              </button>
            )}
            {result && onAttachEvidenceNote && (
              <button
                type="button"
                onClick={handleAttach}
                className="px-3 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-white font-medium inline-flex items-center gap-1.5"
              >
                <CheckCircle2 className="w-3.5 h-3.5" />
                Attach as Evidence Note
              </button>
            )}
            <button
              type="button"
              onClick={onClose}
              className="px-3 py-1.5 rounded bg-[#1e2c45] hover:bg-[#283b5c] text-white"
            >
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

