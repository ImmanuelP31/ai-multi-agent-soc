import { describe, expect, it } from "vitest";

import {
  normalizeAlert,
  normalizeAlertStats,
  normalizeSeverity,
} from "../services/api";

describe("SOC API normalization", () => {
  it("normalizes canonical alert fields and numeric confidence", () => {
    const alert = normalizeAlert({
      event_id: 42,
      incident_id: "incident-42",
      ip: "192.0.2.42",
      severity: "critical",
      confidence: "0.91",
      threat_intelligence: { confidence: "0.88" },
    });

    expect(alert.event_id).toBe("42");
    expect(alert.source_ip).toBe("192.0.2.42");
    expect(alert.severity).toBe("CRITICAL");
    expect(alert.confidence).toBe(0.91);
    expect(alert.threat_intelligence.confidence).toBe(0.88);
  });

  it("uses the canonical severity order for sparse stats", () => {
    const stats = normalizeAlertStats({
      severity_counts: { HIGH: 2 },
    });

    expect(stats.severity_chart).toEqual([
      { severity: "LOW", count: 0 },
      { severity: "MEDIUM", count: 0 },
      { severity: "HIGH", count: 2 },
      { severity: "CRITICAL", count: 0 },
    ]);
    expect(normalizeSeverity("unexpected")).toBe("UNKNOWN");
  });
});
