import { useEffect, useState } from "react";
import api from "../services/api";

function AlertTable() {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);

  const fetchAlerts = () => {
    api
      .get("/alerts/?limit=100")
      .then((res) => {
        setAlerts(res.data);
        setError(false);
        setLoading(false);
      })
      .catch((err) => {
        console.error(err);
        setError(true);
        setLoading(false);
      });
  };

  useEffect(() => {
    fetchAlerts();
    const interval = setInterval(fetchAlerts, 10000);
    return () => clearInterval(interval);
  }, []);

  const formatTime = (timestamp) => {
    if (!timestamp) return "-";
    const date = new Date(timestamp);
    return Number.isNaN(date.getTime()) ? timestamp : date.toLocaleString();
  };

  return (
    <div className="card overflow-hidden p-0">
      <div className="flex items-center justify-between gap-3 border-b border-border px-5 py-4">
        <h2 className="panel-title">Security Alerts</h2>
        {error && <span className="text-xs text-danger">Could not load alerts</span>}
      </div>

      <div className="overflow-x-auto">
        <table className="min-w-full table-fixed text-left text-sm">
          <thead className="bg-slate-950/60 text-xs uppercase tracking-wide text-slate-400">
            <tr>
              <th className="w-16 px-5 py-3 font-semibold">ID</th>
              <th className="px-5 py-3 font-semibold">Event</th>
              <th className="w-28 px-5 py-3 font-semibold">Severity</th>
              <th className="w-36 px-5 py-3 font-semibold">IP</th>
              <th className="w-52 px-5 py-3 font-semibold">Timestamp</th>
            </tr>
          </thead>

          <tbody className="divide-y divide-border">
            {loading && (
              <tr>
                <td colSpan="5" className="px-5 py-10 text-center text-slate-400">
                  Loading alerts...
                </td>
              </tr>
            )}

            {!loading && alerts.length === 0 && (
              <tr>
                <td colSpan="5" className="px-5 py-10 text-center text-slate-400">
                  No alerts yet. Run the simulator to generate SOC events.
                </td>
              </tr>
            )}

            {alerts.map((alert) => (
              <tr key={alert.id} className="hover:bg-slate-800/40">
                <td className="px-5 py-3 text-slate-400">{alert.id}</td>
                <td className="truncate px-5 py-3 text-slate-100">{alert.event || "-"}</td>
                <td className="px-5 py-3">
                  <span className="rounded border border-slate-700 px-2 py-1 text-xs font-semibold text-slate-200">
                    {alert.severity || "LOW"}
                  </span>
                </td>
                <td className="truncate px-5 py-3 text-slate-300">{alert.ip || "-"}</td>
                <td className="truncate px-5 py-3 text-slate-400">
                  {formatTime(alert.timestamp)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default AlertTable;
