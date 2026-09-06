"""Entity baselines: history context only, never a score.

Tracks per-user prior-window counts so scoring can report whether an entity
had enough history. Falls back to global counts for new entities.
"""

from app.services.ueba.config import UebaConfig


def assess(observations: list[dict], config: UebaConfig | None = None) -> dict[str, dict]:
    """Return {entity_key: {status, history_windows, history_events}} in
    chronological order. Status transitions COLD_START -> INSUFFICIENT_HISTORY
    -> READY as history accumulates. Deterministic."""
    config = config or UebaConfig()
    seen_windows: dict[str, int] = {}
    seen_events: dict[str, int] = {}
    result: dict[str, dict] = {}
    for obs in sorted(observations, key=lambda o: (o["window_start"], o["entity_key"])):
        user = obs["entity_key"]
        w, n = seen_windows.get(user, 0), seen_events.get(user, 0)
        if w == 0 and n == 0:
            status = "COLD_START"
        elif w < config.min_history_windows or n < config.min_history_events:
            status = "INSUFFICIENT_HISTORY"
        else:
            status = "READY"
        result[f"{user}|{obs['window_start'].isoformat()}"] = {
            "status": status, "history_windows": w, "history_events": n,
        }
        seen_windows[user] = w + 1
        seen_events[user] = n + obs["event_count"]
    return result
