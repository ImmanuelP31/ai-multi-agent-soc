import { useEffect, useState, useRef } from "react";

const WS_URL = import.meta.env.VITE_WS_URL || "ws://127.0.0.1:8000/ws/live-alerts";

const SEVERITY_COLOR = {
  CRITICAL: "border-red-500 bg-red-950",
  HIGH:     "border-orange-500 bg-orange-950",
  MEDIUM:   "border-yellow-500 bg-yellow-950",
  LOW:      "border-green-600 bg-green-950",
};

const SEVERITY_TEXT = {
  CRITICAL: "text-red-400",
  HIGH:     "text-orange-400",
  MEDIUM:   "text-yellow-400",
  LOW:      "text-green-400",
};

export default function LiveFeed() {
  const [alerts, setAlerts]       = useState([]);
  const [status, setStatus]       = useState("connecting"); // connecting | connected | disconnected
  const socketRef                 = useRef(null);
  const reconnectTimer            = useRef(null);

  const connect = () => {
    // Clean up any existing socket
    if (socketRef.current) {
      socketRef.current.close();
    }

    setStatus("connecting");
    const socket = new WebSocket(WS_URL);
    socketRef.current = socket;

    socket.onopen = () => {
      setStatus("connected");
      // Clear any pending reconnect
      if (reconnectTimer.current) clearTimeout(reconnectTimer.current);
    };

    socket.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        setAlerts((prev) => [data, ...prev.slice(0, 19)]); // keep last 20
      } catch (e) {
        console.error("Failed to parse alert:", e);
      }
    };

    socket.onerror = () => {
      setStatus("disconnected");
    };

    socket.onclose = () => {
      setStatus("disconnected");
      // Auto-reconnect after 3 seconds
      reconnectTimer.current = setTimeout(() => connect(), 3000);
    };
  };

  useEffect(() => {
    connect();
    return () => {
      if (socketRef.current) socketRef.current.close();
      if (reconnectTimer.current) clearTimeout(reconnectTimer.current);
    };
  }, []);

  const statusDot = {
    connecting:   "bg-yellow-400 animate-pulse",
    connected:    "bg-green-400",
    disconnected: "bg-red-500 animate-pulse",
  }[status];

  return (
    <div className="bg-gray-900 p-4 rounded-xl border border-cyan-500 shadow-lg">

      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-cyan-400 text-xl font-bold">Live Threat Feed</h2>
        <div className="flex items-center gap-2">
          <span className={`w-2.5 h-2.5 rounded-full ${statusDot}`} />
          <span className="text-xs text-gray-400 capitalize">{status}</span>
        </div>
      </div>

      {/* Empty state */}
      {alerts.length === 0 && (
        <p className="text-gray-500 text-sm text-center py-6">
          {status === "connected"
            ? "Waiting for alerts... Run attack_simulator.py to generate events."
            : "Connecting to SOC stream..."}
        </p>
      )}

      {/* Alert cards */}
      <div className="space-y-3 max-h-[480px] overflow-y-auto pr-1">
        {alerts.map((alert, index) => {
          const sev      = alert.severity || "LOW";
          const cardCls  = SEVERITY_COLOR[sev] || "border-gray-600 bg-gray-900";
          const textCls  = SEVERITY_TEXT[sev]  || "text-gray-400";

          return (
            <div
              key={index}
              className={`p-3 rounded-lg border ${cardCls} transition-all`}
            >
              <div className="flex justify-between items-start">
                <p className={`font-bold text-sm ${textCls}`}>
                  {alert.event?.replace(/_/g, " ").toUpperCase()}
                </p>
                <span className={`text-xs font-semibold px-2 py-0.5 rounded ${textCls} border ${cardCls}`}>
                  {sev}
                </span>
              </div>

              <div className="mt-1 grid grid-cols-2 gap-x-4 text-xs text-gray-400">
                <span>IP: {alert.ip || "—"}</span>
                <span>User: {alert.user || "—"}</span>
              </div>

              {alert.mitre_attack && (
                <p className="mt-1 text-xs text-purple-400 truncate">
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
                <p className="mt-1 text-xs text-gray-600">
                  {new Date(typeof alert.timestamp === "number"
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
