import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import AlertTable from "../components/AlertTable";
import LiveFeed from "../components/LiveFeed";
import SequencePredictions from "../components/SequencePredictions";
import SeverityChart from "../components/SeverityChart";
import StatsCards from "../components/StatsCards";
import { socQueryKeys } from "../hooks/useSocQueries";

const apiMocks = vi.hoisted(() => ({
  fetchAlertStats: vi.fn(),
  fetchAlerts: vi.fn(),
}));

vi.mock("../services/api", async (importOriginal) => {
  const actual = await importOriginal();
  return { ...actual, ...apiMocks };
});

function createTestClient() {
  return new QueryClient({
    defaultOptions: {
      queries: { retry: false, refetchInterval: false },
    },
  });
}

function renderWithClient(children, client = createTestClient()) {
  return {
    client,
    ...render(
      <QueryClientProvider client={client}>{children}</QueryClientProvider>,
    ),
  };
}

class FakeWebSocket {
  static instances = [];

  constructor(url) {
    this.url = url;
    FakeWebSocket.instances.push(this);
  }

  close() {
    this.onclose?.();
  }

  open() {
    this.onopen?.();
  }

  sendMessage(value) {
    this.onmessage?.({ data: JSON.stringify(value) });
  }
}

describe("dashboard data flow", () => {
  beforeEach(() => {
    apiMocks.fetchAlertStats.mockReset();
    apiMocks.fetchAlerts.mockReset();
    FakeWebSocket.instances = [];
    vi.stubGlobal("WebSocket", FakeWebSocket);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("shares one stats request between cards and chart", async () => {
    apiMocks.fetchAlertStats.mockResolvedValue({
      total_alerts: 12,
      critical_count: 2,
      malware_count: 3,
      severity_chart: [
        { severity: "LOW", count: 7 },
        { severity: "MEDIUM", count: 2 },
        { severity: "HIGH", count: 1 },
        { severity: "CRITICAL", count: 2 },
      ],
    });

    renderWithClient(
      <>
        <StatsCards />
        <SeverityChart />
      </>,
    );

    expect(await screen.findByText("12")).toBeInTheDocument();
    expect(screen.getByText("Severity Distribution")).toBeInTheDocument();
    expect(apiMocks.fetchAlertStats).toHaveBeenCalledTimes(1);
  });

  it("shows the alert loading state", () => {
    apiMocks.fetchAlerts.mockReturnValue(new Promise(() => {}));

    renderWithClient(<AlertTable />);

    expect(screen.getByText("Loading alerts...")).toBeInTheDocument();
  });

  it("shows a normalized alert query error", async () => {
    apiMocks.fetchAlerts.mockRejectedValue(new Error("offline"));

    renderWithClient(<AlertTable />);

    expect(await screen.findByText("Could not load alerts")).toBeInTheDocument();
  });

  it("shares alerts and renders numeric sequence confidence", async () => {
    apiMocks.fetchAlerts.mockResolvedValue([
      {
        id: 7,
        event_id: "event-7",
        incident_id: "incident-7",
        event: "port_scan",
        severity: "HIGH",
        source_ip: "192.0.2.7",
        predicted_next_attack: "PortScan",
        confidence: 0.812,
        investigation_method: "lstm_sequence_model",
      },
    ]);

    renderWithClient(
      <>
        <AlertTable />
        <SequencePredictions />
      </>,
    );

    expect(await screen.findByText("PortScan")).toBeInTheDocument();
    expect(screen.getByText("81.2%")).toBeInTheDocument();
    expect(screen.getByText("192.0.2.7")).toBeInTheDocument();
    expect(apiMocks.fetchAlerts).toHaveBeenCalledTimes(1);
  });

  it("updates alert caches and invalidates REST data on a WebSocket event", () => {
    const client = createTestClient();
    client.setQueryData(socQueryKeys.alertList(100), []);
    client.setQueryData(socQueryKeys.stats, { total_alerts: 0 });
    renderWithClient(<LiveFeed />, client);

    const socket = FakeWebSocket.instances[0];
    act(() => socket.open());
    expect(screen.getByText("connected")).toBeInTheDocument();

    act(() => {
      socket.sendMessage({
        event_id: "event-live",
        incident_id: "incident-live",
        event: "port_scan",
        severity: "high",
        source_ip: "192.0.2.50",
        confidence: "0.75",
        threat_intelligence: {
          technique_id: "T1046",
          technique_name: "Network Service Discovery",
        },
      });
    });

    expect(screen.getByText("PORT SCAN")).toBeInTheDocument();
    expect(screen.getByText("T1046 - Network Service Discovery")).toBeInTheDocument();
    expect(client.getQueryData(socQueryKeys.alertList(100))[0]).toMatchObject({
      event_id: "event-live",
      source_ip: "192.0.2.50",
      severity: "HIGH",
      confidence: 0.75,
    });
    expect(client.getQueryState(socQueryKeys.stats).isInvalidated).toBe(true);
    expect(client.getQueryState(socQueryKeys.alertList(100)).isInvalidated).toBe(
      true,
    );
  });
});
