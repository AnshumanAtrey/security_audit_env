# SecurityAuditEnv — Brutal Honest Weaknesses

## Real-world utility (30% weight)

- It's a **simulation**, not real infrastructure. All tool outputs are hardcoded strings from `tools.py` — there's no actual network, no real MySQL, no real Tomcat.
- A judge who digs into `tools.py` will see it's essentially a lookup table returning pre-written text.
- The "realistic" outputs are still static templates, not dynamic responses.
- Compared to CyberBattleSim or PenGym that have actual network graphs, this is a glorified text adventure.

## Task & grader quality (25% weight)

- Grading is based on **matching against hardcoded ground truth**. Real-world VAPT doesn't have a fixed answer key.
- Easy scenario is too easy — a regex parser scores 1.00. Zero challenge.
- Only 19 total vulnerabilities across 3 scenarios (3+6+10). Small dataset, limited variety.
- Compliance mapping (PCI-DSS/SOC2) is a static lookup table, not real compliance reasoning.

## Environment design (20% weight)

- Environment is **stateless beyond the current episode**. No persistence, no learning across runs.
- Tool outputs are deterministic — same scan always returns same text. No randomness or variation (even with seed support, the outputs don't actually vary).
- Action space is limited: only 10 predefined tools. No free-form commands, no shell access, no ability to chain custom payloads.
- "Progressive discovery" is just an if-check on `hidden_until` — not a real network topology.

## Code quality (15% weight)

- `tools.py` at 779 lines is a massive file of hardcoded string templates — hard to maintain.
- `scenarios.py` at 561 lines is similarly a big data dump.
- No type hints on some internal functions.
- `openenv_security_audit_env.egg-info` directory is committed to the repo (sloppy).

## Creativity (10% weight)

- Creativity is in the **design and framing**, not in the technical implementation. Under the hood, it's a state machine with string lookups.

## What could beat us

- An environment with **real infrastructure** (actual Docker containers, real databases, real web servers).
- An environment with **dynamic/procedural tasks** (not hardcoded scenarios).
- An environment in a higher-impact domain (code review, medical, legal) with more complex grading.

## Overall: 7.5/10 estimated
