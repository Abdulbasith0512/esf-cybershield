import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { ApiError, getEvent, getHealth, listEvents } from "@/lib/api-client";

const BASE = "http://localhost:8000";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

describe("api-client", () => {
  beforeEach(() => {
    process.env.NEXT_PUBLIC_API_BASE_URL = BASE;
    vi.stubGlobal("fetch", vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("returns parsed health on success", async () => {
    vi.mocked(fetch).mockResolvedValue(jsonResponse({ status: "healthy", service: "esf" }));
    await expect(getHealth()).resolves.toEqual({ status: "healthy", service: "esf" });
    expect(fetch).toHaveBeenCalledWith(
      `${BASE}/health`,
      expect.objectContaining({ headers: { "Content-Type": "application/json" } }),
    );
  });

  it("encodes event-list filters as query params", async () => {
    vi.mocked(fetch).mockResolvedValue(
      jsonResponse({ items: [], page: 2, page_size: 25, total: 0, pages: 1 }),
    );
    const res = await listEvents({ page: 2, page_size: 25, event_type: "authentication" });
    expect(res.page).toBe(2);
    const url = vi.mocked(fetch).mock.calls[0][0] as string;
    expect(url).toContain("/api/v1/events?");
    expect(url).toContain("page=2");
    expect(url).toContain("event_type=authentication");
  });

  it("throws ApiError with status on HTTP errors", async () => {
    vi.mocked(fetch).mockResolvedValue(jsonResponse({ detail: "event not found" }, 404));
    const err = await getEvent("missing").catch((e) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).status).toBe(404);
  });

  it("throws ApiError status 0 when the API is unreachable", async () => {
    vi.mocked(fetch).mockRejectedValue(new TypeError("fetch failed"));
    const err = await getHealth().catch((e) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).status).toBe(0);
  });
});
