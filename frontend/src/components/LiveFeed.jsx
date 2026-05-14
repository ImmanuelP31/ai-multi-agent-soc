import { useEffect, useRef, useState } from "react";

const WS_URL =
  import.meta.env.VITE_WS_URL ||
  `${window.location.protocol === "https:" ? "wss" : "ws"}://${window.location.host}/ws/live-alerts`;

const SEVERITY_COLOR = {
  CRITICAL: "border-red-500 bg-red-950",
  HIGH: "border-orange-500 bg-orange-950",
  MEDIUM: "border-yellow-500 bg-yellow-950",
  LOW: "border-green-600 bg-green-950",
};

const SEVERITY_TEXT = {
  CRITICAL: "text-red-400",
  HIGH: "text-orange-400",
  MEDIUM: "text-yellow-400",
  LOW: "text-green-400",
};

export default function LiveFeed() {
  const [alerts, setAlerts] = useState([]);
  const [status, setStatus] = useState("connecting");
  const socketRef = useRef(null);
  const reconnectTimer = useRef(null);
  const stoppedRef = useRef(false);

  useEffect(() => {
    stoppedRef.current = false;

    const connect = () => {
      if (stoppedRef.current) return;

      if (socketRef.current) {
        socketRef.current.close();
      }

      setStatus("connecting");
      const socket = new WebSocket(WS_URL);
      socketRef.current = socket;

      socket.onopen = () => {
        setStatus("connected");
        if (reconnectTimer.current) clearTimeout(reconnectTimer.current);
      };

      socket.onmessage = (event) => {
        let data;

        try {
          data = JSON.parse(event.data);
        } catch {
          data = {
            event: "stream_message",
            severity: "LOW",
            message: String(event.data),
          };
        }

        setAlerts((prev) => [data, ...prev.slice(0, 19)]);
      };

      socket.onerror = () => {
        setStatus("disconnected");
      };

      socket.onclose = () => {
        setStatus("disconnected");
        if (!stoppedRef.current) {
          reconnectTimer.current = setTimeout(connect, 3000);
        }
      };
    };

    connect();

    return () => {
      stoppedRef.current = true;
      if (socketRef.current) socketRef.current.close();
      if (reconnectTimer.current) clearTimeout(reconnectTimer.current);
    };
  }, []);

  const statusDot = {
    connecting: "bg-yellow-400 animate-pulse",
    connected: "bg-green-400",
    disconnected: "bg-red-500 animate-pulse",
  }[status];

  return (
    <div className="card">
      <div className="mb-4 flex items-center justify-between">
        <h2 className="panel-title">Live Threat Feed</h2>
        <div className="flex items-center gap-2">
          <span className={`h-2.5 w-2.5 rounded-full ${statusDot}`} />
          <span className="text-xs capitalize text-slate-400">{status}</span>
        </div>
      </div>

      {alerts.length === 0 && (
        <p className="py-6 text-center text-sm text-slate-500">
          {status === "connected"
            ? "Waiting for alerts... Run attack_simulator.py to generate events."
            : "Connecting to SOC stream..."}
        </p>
      )}

      <div className="max-h-[480px] space-y-3 overflow-y-auto pr-1">
        {alerts.map((alert, index) => {
          const sev = alert.severity || "LOW";
          const cardCls = SEVERITY_COLOR[sev] || "border-gray-600 bg-gray-900";
          const textCls = SEVERITY_TEXT[sev] || "text-gray-400";

          return (
            <div key={index} className={`rounded-lg border p-3 ${cardCls}`}>
              <div className="flex items-start justify-between gap-3">
                <p className={`truncate text-sm font-bold ${textCls}`}>
                  {alert.event?.replace(/_/g, " ").toUpperCase() || "SYSTEM"}
                </p>
                <span className={`rounded border px-2 py-0.5 text-xs font-semibold ${textCls}`}>
                  {sev}
                </span>
              </div>

              <div className="mt-1 grid grid-cols-2 gap-x-4 text-xs text-slate-400">
                <span className="truncate">IP: {alert.ip || "-"}</span>
                <span className="truncate">User: {alert.user || "-"}</span>
              </div>

              {alert.message && (
                <p className="mt-1 text-xs text-slate-300">{alert.message}</p>
              )}

              {alert.mitre_attack && (
                <p className="mt-1 truncate text-xs text-purple-400">
                  {alert.mitre_attack}
                </p>
              )}

              {alert.predicted_next_attack && (
                <p className="mt-0.5 text-xs text-cyan-400">
                  Next predicted: {alert.predicted_next_attack}
                  {alert.confidence ? ` (${(alert.confidence * 100).toFixed(1)}%)` : ""}
                </p>
              )}

              {alert.timestamp && (
                <p className="mt-1 text-xs text-slate-500">
                  {new Date(
                    typeof alert.timestamp === "number"
                      ? alert.timestamp * 1000
                      : alert.timestamp
                  ).toLocaleTimeString()}
                </p>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
