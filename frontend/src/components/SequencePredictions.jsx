import { useEffect, useState } from "react";
import api from "../services/api";

export default function SequencePredictions() {
  const [predictions, setPredictions] = useState([]);
  const [loading, setLoading] = useState(true);

  const fetchPredictions = () => {
    api
      .get("/alerts/?limit=20")
      .then((res) => {
        const withPredictions = res.data
          .filter((a) => a.predicted_next_attack && a.predicted_next_attack !== "BENIGN")
          .slice(0, 5);
        setPredictions(withPredictions);
        setLoading(false);
      })
      .catch((err) => {
        console.error(err);
        setLoading(false);
      });
  };

  useEffect(() => {
    fetchPredictions();
    const interval = setInterval(fetchPredictions, 10000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="card">
      <h2 className="panel-title mb-4">
        AI Attack Predictions
        <span className="ml-2 text-xs font-normal text-slate-500">
          (LSTM sequence model)
        </span>
      </h2>

      {loading && <p className="muted">Loading predictions...</p>}

      {!loading && predictions.length === 0 && (
        <p className="muted">
          No predictions yet - run attack_simulator.py to generate events.
        </p>
      )}

      <ul className="space-y-3">
        {predictions.map((alert, idx) => (
          <li key={idx} className="rounded-lg border border-border bg-slate-950/50 p-3">
            <div className="flex justify-between gap-4">
              <div className="min-w-0">
                <p className="text-sm font-semibold text-white">
                  Predicted next:{" "}
                  <span className="text-cyan-400">{alert.predicted_next_attack}</span>
                </p>
                <p className="mt-0.5 text-xs text-slate-400">
                  Triggered by:{" "}
                  <span className="text-yellow-400">{alert.event?.replace(/_/g, " ")}</span>
                  {" "}from {alert.ip || "unknown IP"}
                </p>
                {alert.investigation && (
                  <p className="mt-1 max-h-8 overflow-hidden text-xs text-slate-500">
                    {alert.investigation}
                  </p>
                )}
              </div>
              {alert.confidence && (
                <span className="whitespace-nowrap text-xs font-bold text-green-400">
                  {(parseFloat(alert.confidence) * 100).toFixed(1)}%
                </span>
              )}
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}
