import { socQueryKeys } from "../hooks/useSocQueries";

export function alertStableKey(alert) {
  return alert.event_id || alert.incident_id || alert.id || null;
}

export function upsertAlert(alerts, incoming, maximum = 100) {
  const incomingKey = alertStableKey(incoming);
  const current = Array.isArray(alerts) ? alerts : [];
  const withoutExisting = incomingKey
    ? current.filter((alert) => alertStableKey(alert) !== incomingKey)
    : current;
  return [incoming, ...withoutExisting].slice(0, maximum);
}

export function refreshAlertCaches(queryClient, alert) {
  queryClient.setQueriesData(
    { queryKey: socQueryKeys.alertLists() },
    (alerts) => upsertAlert(alerts, alert),
  );
  queryClient.invalidateQueries({ queryKey: socQueryKeys.stats });
  queryClient.invalidateQueries({ queryKey: socQueryKeys.alertLists() });
}
