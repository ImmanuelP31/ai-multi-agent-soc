import { useSequencePredictions } from "../hooks/useSocQueries";
import { alertStableKey } from "../services/alertCache";

export default function SequencePredictions() {
  const {
    data: predictions = [],
    isPending: loading,
    isError: error,
  } = useSequencePredictions();

  return (
    <div className="card">
      <h2 className="panel-title mb-4">
        AI Attack Predictions
        <span className="ml-2 text-xs font-normal text-slate-500">
          (LSTM when available)
        </span>
      </h2>

      {loading && <p className="muted">Loading predictions...</p>}

      {error && <p className="muted text-danger">Could not load predictions</p>}

      {!loading && !error && predictions.length === 0 && (
        <p className="muted">
          No predictions yet - run attack_simulator.py to generate events.
        </p>
      )}

      <ul className="space-y-3">
        {predictions.map((alert) => (
          <li
            key={alertStableKey(alert)}
            className="rounded-lg border border-border bg-slate-950/50 p-3"
          >
            <div className="flex justify-between gap-4">
              <div className="min-w-0">
                <p className="text-sm font-semibold text-white">
                  {alert.predicted_next_attack ? "Predicted next:" : "Prediction unavailable:"}{" "}
                  <span className="text-cyan-400">
                    {alert.predicted_next_attack || "trained model not loaded"}
                  </span>
                </p>
                {alert.investigation_method && (
                  <p className="mt-0.5 text-[11px] uppercase text-slate-500">
                    {alert.investigation_method === "lstm_sequence_model"
                      ? "LSTM sequence model"
                      : `LSTM sequence model unavailable${
                          alert.lstm_status ? ` - ${alert.lstm_status.replace(/_/g, " ")}` : ""
                        }`}
                  </p>
                )}
                <p className="mt-0.5 text-xs text-slate-400">
                  Triggered by:{" "}
                  <span className="text-yellow-400">{alert.event?.replace(/_/g, " ")}</span>
                  {" "}from {alert.source_ip || "unknown IP"}
                </p>
                {alert.investigation && (
                  <p className="mt-1 max-h-8 overflow-hidden text-xs text-slate-500">
                    {alert.investigation}
                  </p>
                )}
              </div>
              {Number.isFinite(alert.confidence) && (
                <span className="whitespace-nowrap text-xs font-bold text-green-400">
                  {(alert.confidence * 100).toFixed(1)}%
                </span>
              )}
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}
