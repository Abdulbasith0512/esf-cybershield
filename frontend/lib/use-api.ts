"use client";

/** Minimal shared-fetch hook: in-flight dedup across components, manual
 *  refresh, explicit loading/error/data states. No polling, no cache library.
 */

import { useCallback, useEffect, useEffectEvent, useState } from "react";

const inflight = new Map<string, Promise<unknown>>();

export interface ApiState<T> {
  data: T | null;
  error: Error | null;
  loading: boolean;
  refresh: () => void;
}

interface Snapshot<T> {
  key: string;
  data: T | null;
  error: Error | null;
}

export function useApi<T>(key: string, fetcher: (signal: AbortSignal) => Promise<T>): ApiState<T> {
  const [snapshot, setSnapshot] = useState<Snapshot<T> | null>(null);
  const [nonce, setNonce] = useState(0);
  const doFetch = useEffectEvent(fetcher);

  useEffect(() => {
    const controller = new AbortController();
    let cancelled = false;

    async function run() {
      let promise = inflight.get(key) as Promise<T> | undefined;
      if (!promise) {
        promise = doFetch(controller.signal).finally(() => {
          if (inflight.get(key) === promise) inflight.delete(key);
        });
        inflight.set(key, promise);
      }
      try {
        const value = await promise;
        if (!cancelled) setSnapshot({ key, data: value, error: null });
      } catch (err) {
        if (cancelled) return;
        if (err instanceof DOMException && err.name === "AbortError") return;
        setSnapshot({ key, data: null, error: err instanceof Error ? err : new Error("Unknown error") });
      }
    }
    run();
    return () => {
      cancelled = true;
      controller.abort();
    };
  }, [key, nonce]);

  const refresh = useCallback(() => {
    inflight.delete(key);
    setNonce((n) => n + 1);
  }, [key]);

  const current = snapshot !== null && snapshot.key === key ? snapshot : null;
  return {
    data: current?.data ?? null,
    error: current?.error ?? null,
    loading: current === null,
    refresh,
  };
}
