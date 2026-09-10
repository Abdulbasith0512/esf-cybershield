import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { render, screen } from "@testing-library/react";
import { Sidebar } from "@/components/layout/sidebar";
import { TopBar } from "@/components/layout/top-bar";

vi.mock("next/navigation", () => ({
  usePathname: () => "/incidents",
}));

function jsonResponse(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

describe("application shell", () => {
  beforeEach(() => {
    process.env.NEXT_PUBLIC_API_BASE_URL = "http://localhost:8000";
    vi.stubGlobal("fetch", vi.fn());
    vi.mocked(fetch).mockResolvedValue(
      jsonResponse({ status: "healthy", service: "esf-cybershield-backend" }),
    );
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("renders every navigation destination in grouped sections", () => {
    render(<Sidebar open={false} onClose={() => {}} />);
    expect(screen.getByText("Operations")).toBeInTheDocument();
    expect(screen.getByText("Detection & Analytics")).toBeInTheDocument();
    for (const label of ["Overview", "Incidents", "Events", "Detection Rules", "MITRE ATT&CK", "UEBA"]) {
      expect(screen.getByRole("link", { name: label })).toBeInTheDocument();
    }
    expect(screen.getByText("ESF CyberShield")).toBeInTheDocument();
  });

  it("marks the active route with aria-current", () => {
    render(<Sidebar open={false} onClose={() => {}} />);
    expect(screen.getByRole("link", { name: "Incidents" })).toHaveAttribute("aria-current", "page");
    expect(screen.getByRole("link", { name: "Events" })).not.toHaveAttribute("aria-current");
  });

  it("top bar shows breadcrumb and live API health", async () => {
    render(<TopBar onMenu={() => {}} />);
    expect(screen.getByText("Incidents")).toBeInTheDocument();
    expect(await screen.findByText("Operational")).toBeInTheDocument();
  });
});
