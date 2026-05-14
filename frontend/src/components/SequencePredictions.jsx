import { useEffect, useState } from "react";
import api from "../services/api";

export default function SequencePredictions() {
  const [predictions, setPredictions] = useState([]);
  const [loading,     setLoading]     = useState(true);

  const fetchPredictions = () => {
    // Fetch latest 5 alerts that have an LSTM prediction
    api.get("/alerts?limit=20")
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
    <div className="bg-gray-900 p-4 rounded-xl border border-cyan-500">
      <h2 className="text-cyan-400 text-xl font-bold mb-4">
        AI Attack Predictions
        <span className="ml-2 text-xs font-normal text-gray-500">(LSTM sequence model)</span>
      </h2>

      {loading && (
        <p className="text-gray-400 text-sm">Loading predictions...</p>
      )}

      {!loading && predictions.length === 0 && (
        <p className="text-gray-500 text-sm">
          No predictions yet — run attack_simulator.py to generate events.
        </p>
      )}

      <ul className="space-y-3">
        {predictions.map((alert, idx) => (
          <li
            key={idx}
            className="bg-gray-800 rounded-lg p-3 border border-gray-700"
          >
            <div className="flex justify-between items-start">
              <div>
                <p className="text-white text-sm font-semibold">
                  Predicted next:{" "}
                  <span className="text-cyan-400">{alert.predicted_next_attack}</span>
                </p>
                <p className="text-gray-400 text-xs mt-0.5">
                  Triggered by:{" "}
                  <span className="text-yellow-400">
                    {alert.event?.replace(/_/g, " ")}
                  </span>
                  {" "}from {alert.ip || "unknown IP"}
                </p>
                {alert.investigation && (
                  <p className="text-gray-500 text-xs mt-1 line-clamp-2">
                    {alert.investigation}
                  </p>
                )}
              </div>
              {alert.confidence && (
                <span className="text-xs font-bold text-green-400 ml-3 whitespace-nowrap">
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