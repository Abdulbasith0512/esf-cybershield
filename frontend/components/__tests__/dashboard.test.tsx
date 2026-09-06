import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { SeverityBadge, StatusDot } from "@/components/ui/badge";
import { EmptyState, ErrorState, LoadingState, UnavailableState } from "@/components/ui/states";
import { EventsTable } from "@/components/dashboard/events-table";
import type { SecurityEvent } from "@/lib/types";

const event: SecurityEvent = {
  id: "11111111-1111-1111-1111-111111111111",
  event_id: "evt-000001",
  timestamp: "2026-09-06T10:21:31Z",
  event_type: "authentication",
  source: "windows",
  host: "WIN-042",
  user: "john.doe",
  source_ip: "192.168.1.20",
  destination_ip: null,
  destination_port: null,
  protocol: null,
  process_name: null,
  parent_process: null,
  command_line: null,
  file_hash: null,
  domain: null,
  url: null,
  bytes_sent: null,
  bytes_received: null,
  status: "failed",
  raw_event: { original_field: "original_value" },
  created_at: "2026-09-06T10:21:32Z",
};

describe("states", () => {
  it("renders loading, error, and empty states distinctly", () => {
    const { unmount } = render(<LoadingState message="Loading security telemetry..." />);
    expect(screen.getByRole("status")).toHaveTextContent("Loading security telemetry...");
    unmount();

    render(<ErrorState message="boom" />);
    expect(screen.getByRole("alert")).toHaveTextContent("Unable to load security telemetry.");
    expect(screen.queryByText("No security events available.")).not.toBeInTheDocument();
  });

  it("renders empty state distinctly from error", () => {
    render(<EmptyState message="No security events available." />);
    expect(screen.getByText("No security events available.")).toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("renders unavailable placeholder without fabricating data", () => {
    render(<UnavailableState feature="Incident queue" />);
    expect(screen.getByText(/backend endpoint not available/)).toBeInTheDocument();
  });
});

describe("severity", () => {
  it("labels every level with text, not color alone", () => {
    for (const level of ["CRITICAL", "HIGH", "MEDIUM", "LOW"]) {
      const { unmount } = render(<SeverityBadge severity={level} />);
      const badge = screen.getByRole("img", { name: `severity ${level}` });
      expect(badge).toHaveTextContent(level);
      unmount();
    }
  });

  it("renders health status dots", () => {
    const { unmount } = render(<StatusDot ok={true} label="API" />);
    expect(screen.getByText("Operational")).toBeInTheDocument();
    unmount();
    render(<StatusDot ok={false} label="API" />);
    expect(screen.getByText("Unavailable")).toBeInTheDocument();
  });
});

describe("events table", () => {
  it("renders event columns and escapes raw strings as text", () => {
    const evil = { ...event, user: "<img src=x onerror=alert(1)>" };
    render(<EventsTable events={[evil]} />);
    expect(screen.getByText("authentication")).toBeInTheDocument();
    expect(screen.getByText("WIN-042")).toBeInTheDocument();
    // Rendered as text, not parsed as HTML.
    expect(document.querySelector("table img")).toBeNull();
    expect(screen.getByText("<img src=x onerror=alert(1)>")).toBeInTheDocument();
  });

  it("renders em-dash placeholders, never blank cells for nulls", () => {
    render(<EventsTable events={[event]} />);
    expect(screen.getAllByText("—").length).toBeGreaterThan(0);
  });
});
