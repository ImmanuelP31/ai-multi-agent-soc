import { useQuery } from "@tanstack/react-query";
import { fetchAlerts, fetchAlertStats } from "../services/api";

export const SOC_REFETCH_INTERVAL = 30000;

export const socQueryKeys = {
  all: ["soc"],
  alerts: () => ["soc", "alerts"],
  alertLists: () => ["soc", "alerts", "list"],
  alertList: (limit = 100) => ["soc", "alerts", "list", { limit }],
  stats: ["soc", "alerts", "stats"],
};

export function useAlertStats() {
  return useQuery({
    queryKey: socQueryKeys.stats,
    queryFn: fetchAlertStats,
    refetchInterval: SOC_REFETCH_INTERVAL,
  });
}

export function useAlerts(limit = 100, options = {}) {
  return useQuery({
    queryKey: socQueryKeys.alertList(limit),
    queryFn: () => fetchAlerts(limit),
    refetchInterval: SOC_REFETCH_INTERVAL,
    ...options,
  });
}

export function selectSequencePredictions(alerts) {
  return alerts
    .filter(
      (alert) =>
        (alert.predicted_next_attack &&
          alert.predicted_next_attack !== "BENIGN") ||
        alert.investigation_method === "lstm_sequence_model_unavailable",
    )
    .slice(0, 5);
}

export function useSequencePredictions() {
  return useAlerts(100, { select: selectSequencePredictions });
}
