import React, { useEffect, useState } from 'react';
import { NavLink, Outlet, useNavigate } from 'react-router-dom';
import {
  Activity,
  AlertTriangle,
  BarChart3,
  Bell,
  Clock,
  Cpu,
  Database,
  FileSearch,
  Globe,
  LayoutDashboard,
  Lock,
  LogOut,
  Menu,
  Radio,
  Search,
  Settings,
  Shield,
  ShieldAlert,
  Sliders,
  User,
  X,
} from 'lucide-react';
import { api, clearStoredAuth, getStoredUser } from '../services/api';
import { useRealtimeStream } from '../hooks/useRealtimeStream';
import { UserProfile } from '../types';
import { SeverityBadge } from '../components/SeverityBadge';
import { formatShortTime } from '../utils/formatters';

interface NavItem {
  to: string;
  label: string;
  icon: React.FC<{ className?: string }>;
}

const NAV_ITEMS: NavItem[] = [
  { to: '/', label: 'Overview Dashboard', icon: LayoutDashboard },
  { to: '/events', label: 'Security Events Explorer', icon: FileSearch },
  { to: '/alerts', label: 'Alerts Management', icon: AlertTriangle },
  { to: '/rules', label: 'Threat Detection Rules', icon: Sliders },
  { to: '/detections', label: 'MITRE ATT&CK Matrix', icon: ShieldAlert },
  { to: '/incidents', label: 'Incident Investigation', icon: Activity },
  { to: '/threat-intelligence', label: 'Threat Intelligence', icon: Globe },
  { to: '/analytics', label: 'Analytics & Reports', icon: BarChart3 },
  { to: '/system', label: 'System Monitoring', icon: Settings },
];

export const MainLayout: React.FC<{ onRealtimeRefresh?: () => void }> = ({
  onRealtimeRefresh,
}) => {
  const navigate = useNavigate();
  const { connectionState, notifications, clearNotifications } =
    useRealtimeStream(onRealtimeRefresh);

  const [sidebarOpen, setSidebarOpen] = useState<boolean>(false);
  const [currentTime, setCurrentTime] = useState<Date>(new Date());
  const [healthStatus, setHealthStatus] = useState<{
    status: string;
    backend_connected: boolean;
    postgresql_connected: boolean;
    enabled_rules: number;
    database: string;
  }>({
    status: 'checking',
    backend_connected: false,
    postgresql_connected: false,
    enabled_rules: 0,
    database: 'checking...',
  });

  // Global search state
  const [searchQuery, setSearchQuery] = useState('');
  const [searchResults, setSearchResults] = useState<any | null>(null);
  const [searchOpen, setSearchOpen] = useState(false);

  // Notification drawer & User menu
  const [notifOpen, setNotifOpen] = useState(false);
  const [userMenuOpen, setUserMenuOpen] = useState(false);
  const [loginModalOpen, setLoginModalOpen] = useState(false);
  const [currentUser, setCurrentUser] = useState<UserProfile | null>(
    getStoredUser() || {
      id: 1,
      username: 'admin',
      email: 'admin@threatlens.local',
      full_name: 'Elena Rostova (SOC Director)',
      role: 'admin',
      is_active: true,
      created_at: new Date().toISOString(),
    }
  );

  // Login modal form
  const [loginUsername, setLoginUsername] = useState('admin');
  const [loginPassword, setLoginPassword] = useState('ThreatLens!Admin2026');
  const [loginError, setLoginError] = useState<string | null>(null);
  const [loginLoading, setLoginLoading] = useState(false);

  useEffect(() => {
    const timer = window.setInterval(() => setCurrentTime(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    const fetchHealth = () => {
      api
        .getSystemHealth()
        .then((res) => {
          setHealthStatus({
            status: res.status || 'degraded',
            backend_connected: Boolean(res.backend_connected),
            postgresql_connected: Boolean(res.database?.postgresql_connected),
            enabled_rules: res.detection_engine?.enabled_rules ?? 0,
            database: res.database?.backend || 'unknown',
          });
        })
        .catch(() => {
          setHealthStatus({
            status: 'offline',
            backend_connected: false,
            postgresql_connected: false,
            enabled_rules: 0,
            database: 'offline',
          });
        });
    };
    fetchHealth();
    const interval = window.setInterval(fetchHealth, 15000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    const q = searchQuery.trim();
    if (q.length < 2) {
      setSearchResults(null);
      return;
    }
    const handle = window.setTimeout(() => {
      api
        .globalSearch(q)
        .then((res) => {
          setSearchResults(res);
          setSearchOpen(true);
        })
        .catch(() => {
          setSearchResults(null);
        });
    }, 220);
    return () => clearTimeout(handle);
  }, [searchQuery]);

  const handleLoginSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoginError(null);
    setLoginLoading(true);
    try {
      const res = await api.login(loginUsername, loginPassword);
      setCurrentUser(res.user);
      setLoginModalOpen(false);
      setUserMenuOpen(false);
    } catch (err: any) {
      setLoginError(err.message || 'Authentication failed');
    } finally {
      setLoginLoading(false);
    }
  };

  const handleQuickProfileSwitch = async (username: string, password: string) => {
    setLoginUsername(username);
    setLoginPassword(password);
    try {
      const res = await api.login(username, password);
      setCurrentUser(res.user);
      setUserMenuOpen(false);
    } catch {
      setLoginModalOpen(true);
    }
  };

  return (
    <div className="min-h-screen flex bg-[#090d16] text-slate-100">
      {/* Mobile Sidebar Backdrop */}
      {sidebarOpen && (
        <div
          onClick={() => setSidebarOpen(false)}
          className="fixed inset-0 bg-black/60 z-40 lg:hidden"
        />
      )}

      {/* Responsive Sidebar Navigation */}
      <aside
        className={`fixed inset-y-0 left-0 z-50 lg:static w-64 shrink-0 bg-[#0c121e] border-r border-[#1e2c45] flex flex-col justify-between transition-transform duration-200 ${
          sidebarOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'
        }`}
      >
        <div>
          {/* Brand Header */}
          <div className="h-16 px-5 flex items-center justify-between gap-3 border-b border-[#1e2c45]">
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded bg-cyan-500/15 border border-cyan-500/40 flex items-center justify-center text-cyan-400">
                <Shield className="w-5 h-5" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <span className="font-bold tracking-tight text-base text-white">
                    THREAT<span className="text-cyan-400">LENS</span>
                  </span>
                  <span className="text-[10px] font-mono uppercase px-1.5 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800/60">
                    SIEM v1.0
                  </span>
                </div>
                <p className="text-[11px] text-slate-400">Security Operations Center</p>
              </div>
            </div>
            <button
              onClick={() => setSidebarOpen(false)}
              className="lg:hidden p-1 text-slate-400 hover:text-white"
              aria-label="Close sidebar"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          {/* Navigation Links */}
          <nav className="p-3 space-y-1" aria-label="Main Navigation">
            <div className="px-3 py-1.5 text-[10px] font-semibold uppercase tracking-wider text-slate-500">
              SOC Operations
            </div>
            {NAV_ITEMS.map((item) => {
              const Icon = item.icon;
              return (
                <NavLink
                  key={item.to}
                  to={item.to}
                  end={item.to === '/'}
                  onClick={() => setSidebarOpen(false)}
                  className={({ isActive }) =>
                    `flex items-center gap-3 px-3 py-2.5 rounded-md text-xs font-medium transition-colors ${
                      isActive
                        ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30'
                        : 'text-slate-400 hover:text-slate-100 hover:bg-[#151f32] border border-transparent'
                    }`
                  }
                >
                  <Icon className="w-4 h-4 shrink-0" />
                  <span>{item.label}</span>
                </NavLink>
              );
            })}
          </nav>
        </div>

        {/* Sidebar Telemetry & Engine Footer */}
        <div className="p-3 m-3 rounded-md bg-[#0f1623] border border-[#1e2c45] space-y-2">
          <div className="flex items-center justify-between text-xs">
            <span className="text-slate-400 flex items-center gap-1.5">
              <Cpu className="w-3.5 h-3.5 text-cyan-400" />
              Rule Engine
            </span>
            <span className="text-emerald-400 font-mono text-[11px]">
              {healthStatus.enabled_rules}/7 ACTIVE
            </span>
          </div>
          <div className="flex items-center justify-between text-xs">
            <span className="text-slate-400 flex items-center gap-1.5">
              <Database className="w-3.5 h-3.5 text-blue-400" />
              PostgreSQL
            </span>
            <span
              className={`font-mono text-[11px] truncate max-w-[120px] ${
                healthStatus.postgresql_connected ? 'text-emerald-400' : 'text-yellow-300'
              }`}
            >
              {healthStatus.postgresql_connected
                ? 'CONNECTED'
                : healthStatus.backend_connected
                ? 'SQLITE FALLBACK'
                : 'OFFLINE'}
            </span>
          </div>
          <div className="pt-1 border-t border-[#1e2c45] flex items-center justify-between text-[11px]">
            <span className="text-slate-400">Stream Mode</span>
            {connectionState === 'websocket_live' ? (
              <span className="inline-flex items-center gap-1 text-emerald-400 font-medium">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                WebSocket Live
              </span>
            ) : (
              <span className="inline-flex items-center gap-1 text-yellow-300 font-medium">
                <span className="w-1.5 h-1.5 rounded-full bg-yellow-400" />
                Polling Fallback
              </span>
            )}
          </div>
        </div>
      </aside>

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Top Navigation Bar */}
        <header className="h-16 bg-[#0c121e] border-b border-[#1e2c45] px-4 sm:px-6 flex items-center justify-between gap-4 sticky top-0 z-30">
          <div className="flex items-center gap-3 flex-1 max-w-lg">
            <button
              onClick={() => setSidebarOpen((prev) => !prev)}
              className="lg:hidden p-2 rounded bg-[#0f1623] border border-[#1e2c45] text-slate-300 hover:text-white"
              aria-label="Toggle sidebar navigation"
            >
              <Menu className="w-4 h-4" />
            </button>
            {/* Global Search Input */}
            <div className="relative w-full">
            <div className="relative flex items-center">
              <Search className="w-4 h-4 text-slate-400 absolute left-3 pointer-events-none" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                onFocus={() => searchResults && setSearchOpen(true)}
                placeholder="Global search IPs, usernames, alert IDs, MITRE techniques, raw logs..."
                className="w-full bg-[#0f1623] border border-[#1e2c45] focus:border-cyan-500/60 rounded-md pl-9 pr-8 py-1.5 text-xs text-slate-100 placeholder-slate-500 focus:outline-none"
              />
              {searchQuery && (
                <button
                  onClick={() => {
                    setSearchQuery('');
                    setSearchResults(null);
                    setSearchOpen(false);
                  }}
                  className="absolute right-2.5 text-slate-400 hover:text-slate-200"
                  title="Clear search"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              )}
            </div>

            {/* Global Search Results Popover */}
            {searchOpen && searchResults && (
              <div className="absolute left-0 right-0 mt-1.5 bg-[#0f1623] border border-[#243554] rounded-md shadow-2xl p-3 z-50 max-h-96 overflow-y-auto space-y-3">
                <div className="flex items-center justify-between border-b border-[#1e2c45] pb-1.5">
                  <span className="text-[11px] font-semibold uppercase tracking-wider text-cyan-400">
                    Global Search Results for "{searchResults.query}"
                  </span>
                  <button
                    onClick={() => setSearchOpen(false)}
                    className="text-xs text-slate-400 hover:text-white"
                  >
                    Close
                  </button>
                </div>

                {searchResults.alerts?.length > 0 && (
                  <div>
                    <div className="text-[10px] font-semibold uppercase text-slate-400 mb-1">
                      Alerts ({searchResults.alerts.length})
                    </div>
                    <div className="space-y-1">
                      {searchResults.alerts.map((a: any) => (
                        <button
                          key={a.id}
                          onClick={() => {
                            setSearchOpen(false);
                            navigate(`/alerts?alertId=${a.id}`);
                          }}
                          className="w-full text-left px-2.5 py-1.5 rounded hover:bg-[#151f32] flex items-center justify-between text-xs"
                        >
                          <span className="truncate pr-2">
                            <span className="font-mono text-cyan-400 mr-2">{a.alert_id}</span>
                            {a.title}
                          </span>
                          <SeverityBadge severity={a.severity} />
                        </button>
                      ))}
                    </div>
                  </div>
                )}

                {searchResults.events?.length > 0 && (
                  <div>
                    <div className="text-[10px] font-semibold uppercase text-slate-400 mb-1">
                      Security Events ({searchResults.events.length})
                    </div>
                    <div className="space-y-1">
                      {searchResults.events.map((ev: any) => (
                        <button
                          key={ev.id}
                          onClick={() => {
                            setSearchOpen(false);
                            navigate(`/events?search=${encodeURIComponent(ev.event_id)}`);
                          }}
                          className="w-full text-left px-2.5 py-1.5 rounded hover:bg-[#151f32] flex items-center justify-between text-xs"
                        >
                          <span className="truncate pr-2">
                            <span className="font-mono text-slate-300 mr-2">{ev.source_ip}</span>
                            {ev.event_category} — {ev.event_type} ({ev.username || 'system'})
                          </span>
                          <SeverityBadge severity={ev.severity} />
                        </button>
                      ))}
                    </div>
                  </div>
                )}

                {searchResults.incidents?.length > 0 && (
                  <div>
                    <div className="text-[10px] font-semibold uppercase text-slate-400 mb-1">
                      Incidents ({searchResults.incidents.length})
                    </div>
                    <div className="space-y-1">
                      {searchResults.incidents.map((inc: any) => (
                        <button
                          key={inc.id}
                          onClick={() => {
                            setSearchOpen(false);
                            navigate(`/incidents?incidentId=${inc.id}`);
                          }}
                          className="w-full text-left px-2.5 py-1.5 rounded hover:bg-[#151f32] flex items-center justify-between text-xs"
                        >
                          <span className="truncate pr-2">
                            <span className="font-mono text-orange-400 mr-2">{inc.incident_id}</span>
                            {inc.title}
                          </span>
                          <SeverityBadge severity={inc.severity} />
                        </button>
                      ))}
                    </div>
                  </div>
                )}

                {searchResults.indicators?.length > 0 && (
                  <div>
                    <div className="text-[10px] font-semibold uppercase text-slate-400 mb-1">
                      Threat Indicators ({searchResults.indicators.length})
                    </div>
                    <div className="space-y-1">
                      {searchResults.indicators.map((ioc: any) => (
                        <button
                          key={ioc.id}
                          onClick={() => {
                            setSearchOpen(false);
                            navigate(
                              `/threat-intelligence?ip=${encodeURIComponent(ioc.indicator_value)}`
                            );
                          }}
                          className="w-full text-left px-2.5 py-1.5 rounded hover:bg-[#151f32] flex items-center justify-between text-xs"
                        >
                          <span className="font-mono text-red-300">{ioc.indicator_value}</span>
                          <span className="text-slate-400">{ioc.threat_type}</span>
                        </button>
                      ))}
                    </div>
                  </div>
                )}

                {!searchResults.alerts?.length &&
                  !searchResults.events?.length &&
                  !searchResults.incidents?.length &&
                  !searchResults.indicators?.length && (
                    <div className="text-xs text-slate-400 py-3 text-center">
                      No matching records found across alerts, events, incidents, or IOCs.
                    </div>
                  )}
              </div>
            )}
            </div>
          </div>

          {/* Right Status & Action Controls */}
          <div className="flex items-center gap-3">
            {/* System Health Indicator */}
            <button
              onClick={() => navigate('/system')}
              className="hidden md:flex items-center gap-2 px-2.5 py-1 rounded bg-[#0f1623] border border-[#1e2c45] text-xs hover:border-cyan-500/40"
              title="System & Ingestion Health"
            >
              <span
                className={`w-2 h-2 rounded-full ${
                  healthStatus.status === 'healthy'
                    ? 'bg-emerald-400'
                    : healthStatus.backend_connected
                    ? 'bg-yellow-400'
                    : 'bg-red-500'
                }`}
              />
              <span className="text-slate-300 font-medium">
                {healthStatus.status === 'healthy'
                  ? 'API & POSTGRES: HEALTHY'
                  : healthStatus.backend_connected
                  ? 'API: ONLINE (PG FALLBACK)'
                  : 'BACKEND: OFFLINE'}
              </span>
            </button>

            {/* Real-Time Stream Indicator */}
            <div className="hidden lg:flex items-center gap-1.5 px-2.5 py-1 rounded bg-[#0f1623] border border-[#1e2c45] text-xs">
              <Radio
                className={`w-3.5 h-3.5 ${
                  connectionState === 'websocket_live' ? 'text-cyan-400' : 'text-yellow-400'
                }`}
              />
              <span className="text-slate-300 font-mono text-[11px]">
                {connectionState === 'websocket_live' ? 'WS LIVE' : 'POLLING'}
              </span>
            </div>

            {/* Live UTC Date & Time Display */}
            <div className="hidden xl:flex items-center gap-1.5 px-2.5 py-1 rounded bg-[#0f1623] border border-[#1e2c45] text-xs font-mono text-slate-300">
              <Clock className="w-3.5 h-3.5 text-cyan-400" />
              <span>{currentTime.toISOString().replace('T', ' ').substring(0, 19)} UTC</span>
            </div>

            {/* Notification Center */}
            <div className="relative">
              <button
                onClick={() => {
                  setNotifOpen(!notifOpen);
                  setUserMenuOpen(false);
                }}
                className="relative p-2 rounded bg-[#0f1623] border border-[#1e2c45] text-slate-300 hover:text-white hover:border-cyan-500/40"
                aria-label="Notification Center"
              >
                <Bell className="w-4 h-4" />
                {notifications.length > 0 && (
                  <span className="absolute -top-1 -right-1 px-1.5 py-0.2 rounded-full bg-red-500 text-[10px] font-bold text-white">
                    {notifications.length}
                  </span>
                )}
              </button>

              {notifOpen && (
                <div className="absolute right-0 mt-2 w-80 bg-[#0f1623] border border-[#243554] rounded-md shadow-2xl p-3 z-50">
                  <div className="flex items-center justify-between border-b border-[#1e2c45] pb-2 mb-2">
                    <span className="text-xs font-semibold text-white">
                      Real-Time SOC Notifications ({notifications.length})
                    </span>
                    {notifications.length > 0 && (
                      <button
                        onClick={clearNotifications}
                        className="text-[11px] text-cyan-400 hover:underline"
                      >
                        Clear All
                      </button>
                    )}
                  </div>
                  {notifications.length === 0 ? (
                    <div className="py-6 text-center text-xs text-slate-400">
                      No new real-time notifications in this session. Trigger a telemetry scenario to watch live alerts stream in.
                    </div>
                  ) : (
                    <div className="space-y-2 max-h-72 overflow-y-auto">
                      {notifications.map((n) => (
                        <div
                          key={n.id}
                          className="p-2 rounded bg-[#151f32] border border-[#1e2c45] text-xs space-y-1"
                        >
                          <div className="flex items-center justify-between">
                            <span className="font-semibold text-slate-100">{n.title}</span>
                            <span className="text-[10px] font-mono text-slate-400">
                              {formatShortTime(n.timestamp)}
                            </span>
                          </div>
                          <p className="text-slate-300 text-[11px]">{n.subtitle}</p>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* User Profile Menu */}
            <div className="relative">
              <button
                onClick={() => {
                  setUserMenuOpen(!userMenuOpen);
                  setNotifOpen(false);
                }}
                className="flex items-center gap-2 px-2.5 py-1.5 rounded bg-[#0f1623] border border-[#1e2c45] hover:border-cyan-500/40 text-xs"
              >
                <User className="w-4 h-4 text-cyan-400" />
                <div className="text-left hidden sm:block">
                  <div className="font-medium text-slate-100 leading-none">
                    {currentUser?.username || 'admin'}
                  </div>
                  <div className="text-[10px] text-cyan-400 uppercase font-mono">
                    {currentUser?.role || 'admin'}
                  </div>
                </div>
              </button>

              {userMenuOpen && (
                <div className="absolute right-0 mt-2 w-64 bg-[#0f1623] border border-[#243554] rounded-md shadow-2xl p-3 z-50 space-y-2.5 text-xs">
                  <div className="border-b border-[#1e2c45] pb-2">
                    <div className="font-semibold text-white">{currentUser?.full_name}</div>
                    <div className="text-slate-400">{currentUser?.email}</div>
                    <div className="mt-1 inline-block px-2 py-0.5 rounded bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 font-mono text-[10px] uppercase">
                      RBAC Role: {currentUser?.role}
                    </div>
                  </div>

                  <div className="space-y-1">
                    <div className="text-[10px] uppercase text-slate-400 font-semibold">
                      Switch SOC Operator Session
                    </div>
                    <button
                      onClick={() => handleQuickProfileSwitch('admin', 'ThreatLens!Admin2026')}
                      className="w-full text-left px-2 py-1.5 rounded hover:bg-[#151f32] text-slate-200 flex items-center justify-between"
                    >
                      <span>admin (SOC Director)</span>
                      <span className="text-[10px] font-mono text-cyan-400">ADMIN</span>
                    </button>
                    <button
                      onClick={() => handleQuickProfileSwitch('analyst', 'ThreatLens!Analyst2026')}
                      className="w-full text-left px-2 py-1.5 rounded hover:bg-[#151f32] text-slate-200 flex items-center justify-between"
                    >
                      <span>analyst (Senior Analyst)</span>
                      <span className="text-[10px] font-mono text-blue-400">ANALYST</span>
                    </button>
                  </div>

                  <div className="pt-2 border-t border-[#1e2c45] flex items-center justify-between">
                    <button
                      onClick={() => {
                        setLoginModalOpen(true);
                        setUserMenuOpen(false);
                      }}
                      className="flex items-center gap-1.5 text-cyan-400 hover:underline"
                    >
                      <Lock className="w-3.5 h-3.5" />
                      JWT Sign In
                    </button>
                    <button
                      onClick={() => {
                        clearStoredAuth();
                        setLoginModalOpen(true);
                        setUserMenuOpen(false);
                      }}
                      className="flex items-center gap-1.5 text-red-400 hover:underline"
                    >
                      <LogOut className="w-3.5 h-3.5" />
                      Sign Out
                    </button>
                  </div>
                </div>
              )}
            </div>
          </div>
        </header>

        {/* Page Content Outlet */}
        <main className="flex-1 p-6 overflow-x-hidden">
          <Outlet />
        </main>
      </div>

      {/* JWT Login Modal */}
      {loginModalOpen && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
          <div className="soc-panel w-full max-w-md p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-[#1e2c45] pb-3">
              <div className="flex items-center gap-2">
                <Shield className="w-5 h-5 text-cyan-400" />
                <h2 className="text-base font-semibold text-white">
                  ThreatLens SOC Operator Authentication
                </h2>
              </div>
              <button
                onClick={() => setLoginModalOpen(false)}
                className="text-slate-400 hover:text-white"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleLoginSubmit} className="space-y-3 text-xs">
              {loginError && (
                <div className="p-2.5 rounded bg-red-500/15 border border-red-500/40 text-red-300">
                  {loginError}
                </div>
              )}
              <div>
                <label className="block text-slate-300 mb-1">Operator Username</label>
                <input
                  type="text"
                  value={loginUsername}
                  onChange={(e) => setLoginUsername(e.target.value)}
                  className="w-full bg-[#090d16] border border-[#1e2c45] rounded px-3 py-2 text-white"
                  required
                />
              </div>
              <div>
                <label className="block text-slate-300 mb-1">Password</label>
                <input
                  type="password"
                  value={loginPassword}
                  onChange={(e) => setLoginPassword(e.target.value)}
                  className="w-full bg-[#090d16] border border-[#1e2c45] rounded px-3 py-2 text-white"
                  required
                />
              </div>
              <div className="p-2.5 rounded bg-[#151f32] border border-[#243554] text-[11px] text-slate-300 space-y-1">
                <div className="font-semibold text-cyan-300">Default Seeded Credentials:</div>
                <div>Admin: <code className="text-white">admin</code> / <code className="text-white">ThreatLens!Admin2026</code></div>
                <div>Analyst: <code className="text-white">analyst</code> / <code className="text-white">ThreatLens!Analyst2026</code></div>
              </div>
              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setLoginModalOpen(false)}
                  className="px-3 py-1.5 rounded border border-[#1e2c45] text-slate-300 hover:bg-[#151f32]"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={loginLoading}
                  className="px-4 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-white font-medium"
                >
                  {loginLoading ? 'Authenticating...' : 'Sign In (JWT)'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

