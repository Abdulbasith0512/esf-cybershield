# Multi-Attack Validation Manifest (frozen)

- Dataset: CICIDS2017 (Canadian Institute for Cybersecurity, UNB).
- Files (complete day files, no subsetting):
  - `data/public/cicids2017/raw/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv`
    286,467 rows — BENIGN 127,537 / PortScan 158,930 — SHA-256
    `7e2ddaa80a5849ba629463296b6128436c161b4a32e8034bb5beae06b0c45e08`
  - `data/public/cicids2017/raw/Tuesday-WorkingHours.pcap_ISCX.csv`
    445,909 rows — BENIGN 432,074 / FTP-Patator 7,938 / SSH-Patator 5,897 — SHA-256
    `ae9c88e10c41a8eb1ff454ae98bc513454925097d0b0b57180f94e79de445815`
- Total: 732,376 rows. Timestamps: day-first 12-hour clock, minute resolution.
- License: CIC public research release (cite Sharafaldin et al. 2018).
- Detector runs on this data: **0**. No precision/recall exists yet.
- Status: FROZEN for Slice 32 adapter + validation design.
- See `docs/multi-attack-dataset-selection.md` for candidates, rationale,
  adapter requirements, and limitations.
