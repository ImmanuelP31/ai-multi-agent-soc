import axios from "axios";

export const API_BASE_URL = (import.meta.env.VITE_API_URL || "").replace(/\/$/, "");

const SEVERITIES = new Set(["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"]);
const SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];

export class ApiError extends Error {
  constructor(message, status = null) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 10000,
});

api.interceptors.response.use(
  (response) => response,
  (error) => {
    const status = error.response?.status ?? null;
    const detail = error.response?.data?.detail;
    const message =
      (typeof detail === "string" && detail) ||
      error.message ||
      "The SOC API request failed";
    return Promise.reject(new ApiError(message, status));
  },
);

function finiteNumber(value, fallback = null) {
  if (value === null || value === undefined || value === "") return fallback;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

export function normalizeSeverity(value) {
  const normalized = String(value || "UNKNOWN").trim().toUpperCase();
  return SEVERITIES.has(normalized) ? normalized : "UNKNOWN";
}

export function normalizeThreatIntelligence(alert = {}) {
  const structured = alert.threat_intelligence || {};
  return {
    technique_id: structured.technique_id || alert.mitre_technique_id || null,
    technique_name:
      structured.technique_name || alert.mitre_technique_name || null,
    tactic: structured.tactic || alert.mitre_tactic || null,
    mapping_version:
      structured.mapping_version || alert.mitre_mapping_version || null,
    match_type:
      structured.match_type ||
      alert.mitre_match_type ||
      alert.threat_intel_method ||
      null,
    confidence: finiteNumber(
      structured.confidence ?? alert.mitre_confidence,
    ),
    evidence: structured.evidence || alert.mitre_evidence || null,
    recommended_action:
      structured.recommended_action || alert.recommended_action || null,
  };
}

export function normalizeAlert(alert = {}) {
  const sourceIp = alert.source_ip || alert.ip || null;
  return {
    ...alert,
    id: finiteNumber(alert.id),
    event_id: alert.event_id ? String(alert.event_id) : null,
    incident_id: alert.incident_id ? String(alert.incident_id) : null,
    source_ip: sourceIp,
    ip: sourceIp,
    severity: normalizeSeverity(alert.severity),
    confidence: finiteNumber(alert.confidence),
    anomaly_score: finiteNumber(alert.anomaly_score),
    mitre_confidence: finiteNumber(alert.mitre_confidence),
    threat_intelligence: normalizeThreatIntelligence(alert),
  };
}

export function normalizeAlertStats(stats = {}) {
  const counts = Object.fromEntries(
    SEVERITY_ORDER.map((severity) => [
      severity,
      finiteNumber(stats.severity_counts?.[severity], 0),
    ]),
  );
  const chartBySeverity = new Map(
    Array.isArray(stats.severity_chart)
      ? stats.severity_chart.map((item) => [
          normalizeSeverity(item.severity),
          finiteNumber(item.count, 0),
        ])
      : [],
  );

  return {
    total_alerts: finiteNumber(stats.total_alerts, 0),
    critical_count: finiteNumber(stats.critical_count, counts.CRITICAL),
    malware_count: finiteNumber(stats.malware_count, 0),
    severity_counts: counts,
    severity_chart: SEVERITY_ORDER.map((severity) => ({
      severity,
      count: chartBySeverity.get(severity) ?? counts[severity],
    })),
  };
}

export async function fetchAlertStats() {
  const response = await api.get("/alerts/stats");
  return normalizeAlertStats(response.data);
}

export async function fetchAlerts(limit = 100) {
  const response = await api.get("/alerts/", { params: { limit } });
  if (!Array.isArray(response.data)) {
    throw new ApiError("The alerts API returned an invalid response");
  }
  return response.data.map(normalizeAlert);
}

export default api;
