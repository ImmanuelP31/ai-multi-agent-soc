import { useEffect, useState } from "react";

export default function LiveFeed() {
  const [alerts, setAlerts] = useState([]);

  useEffect(() => {
    const socket = new WebSocket(
      "ws://127.0.0.1:8000/ws/live-alerts"
    );

    socket.onopen = () => {
      console.log("Connected to SOC stream");
    };

    socket.onmessage = (event) => {
      const data = JSON.parse(event.data);

      setAlerts((prev) => [data, ...prev.slice(0, 9)]);
    };

    socket.onerror = (err) => {
      console.error("WebSocket Error:", err);
    };

    socket.onclose = () => {
      console.log("Socket Closed");
    };

    return () => socket.close();
  }, []);

  return (
    <div className="bg-gray-900 p-4 rounded-xl border border-cyan-500 shadow-lg">
      <h2 className="text-cyan-400 text-xl font-bold mb-4">
        Live Threat Feed
      </h2>

      <div className="space-y-3">
        {alerts.map((alert, index) => (
          <div
            key={index}
            className="bg-black p-3 rounded-lg border border-red-500"
          >
            <p className="text-red-400 font-bold">
              {alert.event}
            </p>

            <p className="text-white">
              Severity: {alert.severity}
            </p>

            <p className="text-gray-400">
              IP: {alert.ip}
            </p>
          </div>
        ))}
      </div>
    </div>
  );
}