import React, { useState, useCallback } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { MainLayout } from './layouts/MainLayout';
import { OverviewDashboardPage } from './pages/OverviewDashboardPage';
import { SecurityEventsExplorerPage } from './pages/SecurityEventsExplorerPage';
import { ThreatDetectionPage } from './pages/ThreatDetectionPage';
import { AlertsManagementPage } from './pages/AlertsManagementPage';
import { IncidentInvestigationPage } from './pages/IncidentInvestigationPage';
import { DetectionRulesPage } from './pages/DetectionRulesPage';
import { ThreatIntelligencePage } from './pages/ThreatIntelligencePage';
import { AnalyticsReportsPage } from './pages/AnalyticsReportsPage';
import { SystemConfigurationPage } from './pages/SystemConfigurationPage';

export const AppRoutes: React.FC = () => {
  const [refreshTick, setRefreshTick] = useState(0);
  const handleRealtimeRefresh = useCallback(() => {
    setRefreshTick((t) => t + 1);
  }, []);

  return (
    <Routes>
      <Route element={<MainLayout onRealtimeRefresh={handleRealtimeRefresh} />}>
        <Route path="/" element={<OverviewDashboardPage refreshTrigger={refreshTick} />} />
        <Route path="/events" element={<SecurityEventsExplorerPage />} />
        <Route path="/detections" element={<ThreatDetectionPage />} />
        <Route path="/alerts" element={<AlertsManagementPage />} />
        <Route path="/alerts/:alertId" element={<AlertsManagementPage />} />
        <Route path="/incidents" element={<IncidentInvestigationPage />} />
        <Route path="/rules" element={<DetectionRulesPage />} />
        <Route path="/threat-intelligence" element={<ThreatIntelligencePage />} />
        <Route path="/analytics" element={<AnalyticsReportsPage />} />
        <Route path="/system" element={<SystemConfigurationPage />} />
        <Route path="/monitoring" element={<SystemConfigurationPage />} />
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

