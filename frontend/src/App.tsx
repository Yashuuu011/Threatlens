import React, { useState, useCallback } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { MainLayout } from './layouts/MainLayout';
import { OverviewDashboardPage } from './pages/OverviewDashboardPage';
import { SecurityEventsExplorerPage } from './pages/SecurityEventsExplorerPage';
import { AlertsManagementPage } from './pages/AlertsManagementPage';
import { DetectionRulesPage } from './pages/DetectionRulesPage';
import { IncidentInvestigationPage } from './pages/IncidentInvestigationPage';
import { SystemConfigurationPage } from './pages/SystemConfigurationPage';

export const AppRoutes: React.FC = () => {
  const [refreshTick, setRefreshTick] = useState(0);
  const handleRealtimeRefresh = useCallback(() => {
    setRefreshTick((t) => t + 1);
  }, []);

  return (
    <Routes>
      <Route element={<MainLayout onRealtimeRefresh={handleRealtimeRefresh} />}>
        {/* 6 Primary SIEM & SOC Modules */}
        <Route path="/" element={<OverviewDashboardPage refreshTrigger={refreshTick} />} />
        <Route path="/events" element={<SecurityEventsExplorerPage />} />
        <Route path="/alerts" element={<AlertsManagementPage />} />
        <Route path="/alerts/:alertId" element={<AlertsManagementPage />} />
        <Route path="/rules" element={<DetectionRulesPage />} />
        <Route path="/incidents" element={<IncidentInvestigationPage />} />
        <Route path="/system" element={<SystemConfigurationPage />} />

        {/* Backward-compatible redirects for merged & consolidated modules */}
        <Route path="/detections" element={<Navigate to="/rules?tab=mitre" replace />} />
        <Route path="/analytics" element={<Navigate to="/?tab=analytics" replace />} />
        <Route path="/threat-intelligence" element={<Navigate to="/alerts" replace />} />
        <Route path="/monitoring" element={<Navigate to="/system" replace />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  );
};

export const App: React.FC = () => {
  return (
    <BrowserRouter>
      <AppRoutes />
    </BrowserRouter>
  );
};

export default App;
