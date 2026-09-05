import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { useAlertStats } from "../hooks/useSocQueries";

const SEVERITY_COLORS = {
  LOW: "#22c55e",
  MEDIUM: "#f59e0b",
  HIGH: "#f97316",
  CRITICAL: "#ef4444",
};

export default function SeverityChart() {
  const { data: stats, isPending: loading, isError: error } = useAlertStats();
  const data = stats?.severity_chart || [];

  return (
    <div className="card">
      <div className="mb-4 flex items-center justify-between gap-3">
        <h2 className="panel-title">Severity Distribution</h2>
        {error && <span className="text-xs text-danger">Could not load stats</span>}
      </div>

      {loading ? (
        <p className="muted py-20 text-center">Loading chart...</p>
      ) : (
        <ResponsiveContainer width="100%" height={260}>
          <BarChart data={data} margin={{ top: 5, right: 20, left: 0, bottom: 5 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
            <XAxis dataKey="severity" tick={{ fill: "#9ca3af", fontSize: 12 }} />
            <YAxis allowDecimals={false} tick={{ fill: "#9ca3af", fontSize: 12 }} />
            <Tooltip
              contentStyle={{
                background: "#111827",
                border: "1px solid #374151",
                borderRadius: 8,
              }}
              labelStyle={{ color: "#e5e7eb" }}
              itemStyle={{ color: "#e5e7eb" }}
            />
            <Bar dataKey="count" radius={[4, 4, 0, 0]}>
              {data.map((entry) => (
                <Cell
                  key={entry.severity}
                  fill={SEVERITY_COLORS[entry.severity] || "#8884d8"}
                />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      )}
    </div>
  );
}
