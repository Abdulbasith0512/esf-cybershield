import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { MetricCard } from "@/components/ui/metric-card";
import { PageHeader } from "@/components/ui/page-header";
import { StatusBadge } from "@/components/ui/status-badge";
import { LoadingSkeleton, TableSkeleton } from "@/components/ui/loading-skeleton";

describe("shared primitives", () => {
  it("renders page header with title and subtitle", () => {
    render(<PageHeader title="Incidents" subtitle="Queue subtitle." />);
    expect(screen.getByRole("heading", { name: "Incidents" })).toBeInTheDocument();
    expect(screen.getByText("Queue subtitle.")).toBeInTheDocument();
  });

  it("renders metric label, value, and hint", () => {
    render(<MetricCard label="Total events" value="1,234" hint="from event store" />);
    expect(screen.getByText("Total events")).toBeInTheDocument();
    expect(screen.getByText("1,234")).toBeInTheDocument();
    expect(screen.getByText("from event store")).toBeInTheDocument();
  });

  it("labels every lifecycle state with text, not color alone", () => {
    for (const status of ["OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED"]) {
      const { unmount } = render(<StatusBadge status={status} />);
      const badge = screen.getByRole("img", { name: `status ${status}` });
      expect(badge).toHaveTextContent(status);
      unmount();
    }
  });

  it("announces skeleton loading states politely", () => {
    const { unmount } = render(<LoadingSkeleton lines={2} />);
    expect(screen.getByRole("status", { name: "Loading content" })).toBeInTheDocument();
    unmount();
    render(<TableSkeleton rows={2} columns={2} />);
    expect(screen.getByRole("status", { name: "Loading table" })).toBeInTheDocument();
  });
});
