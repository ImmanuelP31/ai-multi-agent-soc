import { useEffect, useRef, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import {
  alertStableKey,
  refreshAlertCaches,
  upsertAlert,
} from "../services/alertCache";
import { normalizeAlert } from "../services/api";

export const WS_URL =
  import.meta.env.VITE_WS_URL ||
  `${window.location.protocol === "https:" ? "wss" : "ws"}://${window.location.host}/ws/live-alerts`;

const MAX_RECONNECT_DELAY = 15000;

function localFeedKey() {
  return globalThis.crypto?.randomUUID?.() || `${Date.now()}-${Math.random()}`;
}

export function useLiveAlerts() {
  const queryClient = useQueryClient();
  const [alerts, setAlerts] = useState([]);
  const [status, setStatus] = useState("connecting");
  const socketRef = useRef(null);
  const reconnectTimer = useRef(null);
  const reconnectAttempt = useRef(0);
  const stoppedRef = useRef(false);

  useEffect(() => {
    stoppedRef.current = false;

    const addToFeed = (alert) => {
      const withKey = {
        ...alert,
        _feed_key: alertStableKey(alert) || localFeedKey(),
      };
      setAlerts((current) => upsertAlert(current, withKey, 20));
    };

    const connect = () => {
      if (stoppedRef.current) return;
      setStatus("connecting");

      const socket = new WebSocket(WS_URL);
      socketRef.current = socket;

      socket.onopen = () => {
        reconnectAttempt.current = 0;
        setStatus("connected");
      };

      socket.onmessage = (message) => {
        try {
          const raw = JSON.parse(message.data);
          const alert = normalizeAlert(raw);
          addToFeed(alert);
          if (alert.event_id && alert.incident_id) {
            refreshAlertCaches(queryClient, alert);
          }
        } catch {
          addToFeed(
            normalizeAlert({
              event: "stream_message",
              severity: "LOW",
              message: String(message.data),
            }),
          );
        }
      };

      socket.onerror = () => setStatus("disconnected");
      socket.onclose = () => {
        if (stoppedRef.current) return;
        setStatus("disconnected");
        const delay = Math.min(
          1000 * 2 ** reconnectAttempt.current,
          MAX_RECONNECT_DELAY,
        );
        reconnectAttempt.current += 1;
        reconnectTimer.current = setTimeout(connect, delay);
      };
    };

    connect();

    return () => {
      stoppedRef.current = true;
      if (reconnectTimer.current) clearTimeout(reconnectTimer.current);
      if (socketRef.current) socketRef.current.close();
    };
  }, [queryClient]);

  return { alerts, status };
}
