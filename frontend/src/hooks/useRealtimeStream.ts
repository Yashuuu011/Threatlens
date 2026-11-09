import { useEffect, useRef, useState, useCallback } from 'react';
import { api } from '../services/api';

export type RealtimeConnectionState =
  | 'websocket_live'
  | 'polling_fallback'
  | 'connecting';

export interface RealtimeNotification {
  id: string;
  type: string;
  timestamp: string;
  title: string;
  subtitle: string;
  severity?: string;
}

export function useRealtimeStream(onStreamUpdate?: () => void) {
  const [connectionState, setConnectionState] = useState<RealtimeConnectionState>('connecting');
  const [notifications, setNotifications] = useState<RealtimeNotification[]>([]);
  const [lastHeartbeat, setLastHeartbeat] = useState<string>(new Date().toISOString());
  const wsRef = useRef<WebSocket | null>(null);
  const pollIntervalRef = useRef<number | null>(null);
  const lastSeqRef = useRef<number>(0);
  const callbackRef = useRef(onStreamUpdate);
  callbackRef.current = onStreamUpdate;

  const pushNotification = useCallback((notif: Omit<RealtimeNotification, 'id'>) => {
    setNotifications((prev) => [
      { ...notif, id: `${Date.now()}-${Math.random().toString(36).slice(2, 7)}` },
      ...prev.slice(0, 29),
    ]);
  }, []);

  const clearNotifications = useCallback(() => {
    setNotifications([]);
  }, []);

  const handleIncomingStreamMessage = useCallback(
    (msg: { seq?: number; type?: string; timestamp?: string; data?: any }) => {
      if (typeof msg.seq === 'number' && msg.seq > lastSeqRef.current) {
        lastSeqRef.current = msg.seq;
      }
      const { type, timestamp, data } = msg;
      const ts = timestamp || new Date().toISOString();

      if (type === 'alert_created' && data) {
        pushNotification({
          type: 'alert_created',
          timestamp: ts,
          title: `New Alert: ${data.alert_id || data.rule_code}`,
          subtitle: data.title || 'Rule detection triggered',
          severity: data.severity || 'high',
        });
        callbackRef.current?.();
      } else if (type === 'alert_status_updated' && data) {
        pushNotification({
          type: 'alert_status_updated',
          timestamp: ts,
          title: `Alert ${data.alert_id} Updated`,
          subtitle: `Status transitioned to ${data.status} by ${data.changed_by}`,
          severity: 'low',
        });
        callbackRef.current?.();
      } else if (type === 'event_ingested' && data) {
        pushNotification({
          type: 'event_ingested',
          timestamp: ts,
          title: `Event Ingested: ${data.event_id || data.event_type}`,
          subtitle: `${data.event_category || 'Telemetry'} from ${data.source_ip || 'host'}`,
          severity: data.severity || 'low',
        });
        callbackRef.current?.();
      } else if (type === 'bulk_events_ingested' && data) {
        pushNotification({
          type: 'bulk_events_ingested',
          timestamp: ts,
          title: `Telemetry Batch Ingested (${data.accepted_count} events)`,
          subtitle: `${data.generated_alerts_count} detection alert(s) triggered`,
          severity: data.generated_alerts_count > 0 ? 'high' : 'info',
        });
        callbackRef.current?.();
      } else if (type === 'incident_created' && data) {
        pushNotification({
          type: 'incident_created',
          timestamp: ts,
          title: `Incident Opened: ${data.incident_id}`,
          subtitle: data.title,
          severity: data.severity || 'high',
        });
        callbackRef.current?.();
      } else if (type === 'incident_updated' && data) {
        pushNotification({
          type: 'incident_updated',
          timestamp: ts,
          title: `Incident ${data.incident_id} Updated`,
          subtitle: `Status: ${data.status} (Assignee: ${data.assigned_analyst || 'Unassigned'})`,
          severity: 'medium',
        });
        callbackRef.current?.();
      } else if (type === 'dashboard_metrics_updated') {
        callbackRef.current?.();
      }
    },
    [pushNotification]
  );

  useEffect(() => {
    let unmounted = false;
    let reconnectTimer: number | null = null;

    const startPollingFallback = () => {
      if (unmounted) return;
      setConnectionState((prev) => (prev === 'websocket_live' ? prev : 'polling_fallback'));
      if (pollIntervalRef.current) return;
      pollIntervalRef.current = window.setInterval(async () => {
        if (unmounted) return;
        setLastHeartbeat(new Date().toISOString());
        try {
          const pollData = await api.pollRealtimeUpdates(lastSeqRef.current);
          if (pollData && Array.isArray(pollData.messages)) {
            for (const m of pollData.messages) {
              handleIncomingStreamMessage(m);
            }
          }
          if (typeof pollData?.latest_seq === 'number' && pollData.latest_seq > lastSeqRef.current) {
            lastSeqRef.current = pollData.latest_seq;
          }
        } catch {
          // ignore transient poll failure
        }
        callbackRef.current?.();
      }, 10000);
    };

    const stopPollingFallback = () => {
      if (pollIntervalRef.current) {
        clearInterval(pollIntervalRef.current);
        pollIntervalRef.current = null;
      }
    };

    const connectWebSocket = () => {
      if (unmounted) return;
      try {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = import.meta.env.VITE_WS_URL
          ? import.meta.env.VITE_WS_URL.startsWith('ws')
            ? import.meta.env.VITE_WS_URL
            : `${protocol}//${window.location.host}${import.meta.env.VITE_WS_URL}`
          : `${protocol}//${window.location.host}/ws`;

        const ws = new WebSocket(wsUrl);
        wsRef.current = ws;

        ws.onopen = () => {
          if (unmounted) return;
          setConnectionState('websocket_live');
          setLastHeartbeat(new Date().toISOString());
          stopPollingFallback();
        };

        ws.onmessage = (evt) => {
          if (unmounted) return;
          setLastHeartbeat(new Date().toISOString());
          try {
            const msg = JSON.parse(evt.data);
            if (msg.type === 'connection_established' && typeof msg.seq === 'number') {
              lastSeqRef.current = msg.seq;
              return;
            }
            handleIncomingStreamMessage(msg);
          } catch {
            // ignore malformed message
          }
        };

        ws.onerror = () => {
          startPollingFallback();
        };

        ws.onclose = () => {
          if (unmounted) return;
          startPollingFallback();
          reconnectTimer = window.setTimeout(connectWebSocket, 8000);
        };
      } catch {
        startPollingFallback();
      }
    };

    connectWebSocket();

    return () => {
      unmounted = true;
      stopPollingFallback();
      if (reconnectTimer) clearTimeout(reconnectTimer);
      if (wsRef.current) {
        try {
          wsRef.current.close();
        } catch {
          // ignore
        }
      }
    };
  }, [handleIncomingStreamMessage]);

  return {
    connectionState,
    notifications,
    lastHeartbeat,
    clearNotifications,
  };
}


