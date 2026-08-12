# Plan — Secret Scanning

> **Architecture amendment (2026-08-11).** Scanning is a **Secrets Manager capability, not an
> agent-access capability**: the engine and every producer live in `sdk-sm` (crate
> `bitwarden-scan`, CLI `bws scan`), and this repo keeps only the read-only MCP serving surface.
> `aac` is agentic access — it ships inside the desktop app and must not carry a scanner. Sections
> below are updated in place; the original §1 argued the engine into this workspace for iteration
> speed, which is a convenience argument, not an architectural one.

**Goal:** Detect hardcoded secrets in a codebase (working tree, staged changes, and git history) with a
deterministic, non-agentic scanner, and serve the results to MCP clients as read-only data. Remediation
loops back through the existing `create_secret` tool, which already carries its own desktop approval.

**Core property:** the agent never runs the scan. Scanning is a precomputed pass whose output the agent
reads. A scan the model chooses to invoke is only as reliable as its decision to invoke it and its
willingness to report faithfully; precomputing makes results deterministic, auditable, and identical for
the same input.

**Scope:** detection engine and producer CLI (`bws scan`) in `sdk-sm`; the findings artifact as the
cross-repo contract; read-only MCP serving via the `resources` primitive in
`crates/ap-cli/src/command/mcp.rs`. There is deliberately **no `aac scan`** — `aac` never scans.

**Out of scope:** live validation of found credentials against provider APIs (trufflehog-style);
git-history rewriting; automated remediation beyond the existing `create_secret` flow; any desktop UI for
findings.

**No changes to `bitwarden/clients`.** Findings contain no vault data, so nothing in this plan touches the
local wire protocol, the approval pipeline, or the desktop app. That is what keeps it cheap.

---

## 1. Architecture

Three pieces, deliberately split so the thing that scans is not the thing that serves — and split
across repos so the thing that ships in the desktop app is not the thing that carries a regex engine.

| Piece | Where | Responsibility |
|-------|-------|----------------|
| Engine | `sdk-sm` → `crates/bitwarden-scan` | Detectors, walkers, finding model, baseline. No SM-API/vault dependency. |
| Producer | `bws scan` (`sdk-sm`) | Runs the engine, writes the findings artifact. Worktree, staged, and history modes. |
| Server | `aac mcp` (this repo) | Reads the artifact from disk, exposes it as one MCP resource + one read-only tool. Never scans. |

The engine is a sibling crate in the `sdk-sm` workspace, **not** part of the `bitwarden` API-client
crate (which the napi/py/wasm wrappers consume — none of them need a regex engine). `aac` does not
depend on the engine at all: the cross-repo contract is the findings artifact JSON (§2), which `aac`
reads through a small schema-versioned mirror module. This keeps `aac`'s bundled binary lean (the same
reason this plan rejects libgit2) and keeps the product boundary honest — scanning is a Secrets Manager
feature usable from CI and pre-commit with no agent anywhere in sight.

### 1.1 Engine layout

```
sdk-sm/crates/bitwarden-scan/src/
├── lib.rs          # ScanRequest / ScanReport entry points
├── rules.rs        # Rule definitions (embedded), rule ids, severities
├── detect.rs       # RegexSet single-pass matching + entropy fallback
├── walk.rs         # Filesystem walk (gitignore-aware, binary/size skips)
├── git.rs          # Patch-stream scan over `git log -p`
├── finding.rs      # Finding struct + stable fingerprint
├── baseline.rs     # Ignore-file load/match
└── report.rs       # Findings artifact (de)serialization, schema version
```

Dependencies: `regex` (RegexSet), `ignore` (ripgrep's gitignore-aware walker), `serde`/`serde_json`,
`sha2` (fingerprints). **No `git2`/`gix`** — parse `git log -p` output from the `git` binary. The
engine stays fully synchronous (no tokio) and free of SM-API dependencies, so it can move or be
published without dragging anything along.

### 1.2 Detection

- ~30 high-precision provider rules (`AKIA`, `ghp_`, `xox[bp]-`, `sk_live_`, `-----BEGIN * PRIVATE KEY`,
  Google API keys, JWTs, …) compiled into one `RegexSet` for a single pass per line.
- Shannon-entropy fallback, gated on assignment to a key-like identifier (`*_key`, `*_token`, `secret*`,
  `password*`) to keep the false-positive rate survivable.
- Path and content allowlists: `*.example`, `*.sample`, lockfiles, minified bundles, anything over a
  size cap. **Test/fixture directories are scanned** — real leaks live in test configs; false positives
  there are what the baseline (§2.1) is for.

### 1.3 Scan modes

Same detectors, three very different budgets. Do not ship one code path for all three.

| Mode | Input | Budget | Consumer |
|------|-------|--------|----------|
| `worktree` | Files on disk | seconds | `bws scan` (the only mode that writes the artifact) |
| `staged` | `git diff --cached` | < 200 ms | pre-commit hook (`bws scan --staged`) |
| `history` | `git log -p` patch stream | minutes | CI, one-time audit (`bws scan --history`) |

History scans the patch stream, not per-commit blob trees — each version of a line is examined once
instead of re-reading unchanged files across every commit.

---

## 2. Findings artifact

Written by producers, read by the server. Also the substrate for the baseline, so it lands before the MCP
work.

```jsonc
{
  "schema_version": 1,
  "generated_at": "2026-08-11T12:00:00Z",
  "repo_root": "/abs/path",
  "head_commit": "abc123…",
  "dirty": true,              // uncommitted changes present at scan time
  "scan_mode": "worktree",    // worktree | staged | history
  "truncated": false,         // finding cap hit
  "findings": [
    {
      "fingerprint": "…",     // stable across rescans
      "rule_id": "aws-access-key-id",
      "severity": "high",
      "path": "src/config.ts",
      "line": 42,
      "column": 18,
      "preview": "AKIA****************",
      "origin": "worktree",   // worktree | history
      "commit": null,         // history only
      "author": null,         // history only
      "first_seen": null      // history only
    }
  ]
}
```

**Invariants:**

1. **Never the matched value.** Location, rule id, and a masked preview only. The agent can read the file
   if it needs the literal; putting the secret in the artifact puts it in the model's context and
   transcript, which is what `run_with_secret`'s scrubbing exists to prevent.
2. **Provenance is mandatory.** `generated_at`, `head_commit`, and `dirty` travel with every response.
   Without them the agent acts on stale findings and reports a hardcoded key the user removed an hour ago.
3. **Absence is not cleanliness.** "Never scanned" and "scanned, zero findings" are distinct states and
   must be distinguishable end-to-end. An empty array served for a repo that was never scanned reads as
   an all-clear, and that is the single worst failure mode in this design.

### 2.1 Fingerprints and baseline

`fingerprint = sha256(rule_id | path | normalized_line)` — deliberately **no commit component**. The
same secret on the same line reappears in every commit that touches the file; keying the fingerprint on
commit would give each occurrence a distinct identity, so suppressing one history finding would take one
baseline entry per commit and the baseline would never converge. Content-keyed, history occurrences of
the same (rule, path, line) collapse into one finding whose earliest commit becomes `first_seen`, and one
baseline entry silences it everywhere — worktree and history alike.

History findings never stop being found, so without a fingerprint-keyed ignore file (`.bitwardenignore`,
gitleaks' `.gitleaksignore` model) the second scan reports the same hundred findings as the first and the
team stops reading the output.

---

## 3. MCP serving

`crates/ap-cli/src/command/mcp.rs` today declares `"capabilities": {"tools": {}}` and handles
`initialize` / `ping` / `tools/list` / `tools/call` in the `handle_request` match.

Add:

- `"capabilities": {"tools": {}, "resources": {}}` — no `subscribe`, no `listChanged`: this server has
  no in-process producer, so it has no reliable change signal and refuses to fake one.
- `resources/list`, `resources/read`
- Resource URI `bitwarden://scan/findings` (JSON: an **envelope** wrapping the §2 artifact)

**Plus a read-only `get_secret_findings` tool.** Resource support varies widely across MCP clients, and
few pull resources into context on their own. The tool is the compatibility path — it reads the
precomputed artifact and **never triggers a scan**, so the non-agentic property holds either way.

**Read-on-demand freshness.** The server resolves the repo root once at startup (`--repo <path>` flag,
else `git rev-parse --show-toplevel` from cwd — MCP clients don't reliably set cwd to the project;
Claude Desktop spawns servers with cwd `/` or `$HOME`); with no repo it serves an explicit `no_repo`
state. The artifact is loaded **from disk on every read**, so served data is always as fresh as the
last `bws scan` with zero cache-invalidation machinery. The envelope's status is one of `no_repo` /
`never_scanned` / `artifact_error` / `ready` (per invariant 3 — absence is never cleanliness), and the
`never_scanned` / `no_repo` states carry a hint that findings are produced by running `bws scan`.
Staleness is the agent's job to check via the artifact's mandatory provenance (`generated_at`,
`head_commit`, `dirty`) — the tool description says so explicitly.

---

## 4. Milestones

| ID | Deliverable | Where | Depends on |
|----|-------------|-------|------------|
| **S1** | `bitwarden-scan` crate: rules, `RegexSet` detection, entropy fallback, gitignore-aware walk; findings artifact (§2) with schema versioning; fingerprints; `.bitwardenignore` baseline; `staged` + `history` modes. | `sdk-sm` | — |
| **S2** | `bws scan [path]` (`Commands` enum, `crates/bws/src/cli.rs`): human + JSON output, `--staged` / `--history [range]`, exit codes 0 clean / 1 findings / 2 error, artifact write + not-gitignored warning. Works without an access token — purely local. | `sdk-sm` | S1 |
| **S3** | Read-only MCP serving (§3): `resources/list` + `resources/read`, `get_secret_findings`, read-on-demand artifact loads, `no_repo` / `never_scanned` / `artifact_error` / `ready` states. `aac` carries a schema-mirror module, not the engine. | this repo | S1 (schema only) |
| **S4** | Pre-commit hook + CI recipe docs; large-repo perf validation of `history` mode. | `sdk-sm` | S2 |

S2 and S3 are independent once S1's artifact schema is fixed, and can run in parallel.

---

## 5. Remediation loop (no new work)

Once findings are served, the existing tools close the loop unchanged: agent reads a finding → calls
`create_secret` (already gated on desktop approval, `mcp.rs:432`) → replaces the literal with a
`bw://secret/<id>` reference → the value is injected at runtime via `run_with_secret`. `create_secret`'s
description already advertises this use ("migrate hardcoded credentials or values from a .env file").

**Optional follow-up (S5):** let `create_secret` accept `{path, line}` in place of `value`, so `aac`
reads the plaintext off disk and hands it to the desktop directly. The secret then never enters the
model's context at all. Small addition, meaningful property — but it changes the local wire protocol and
therefore does touch `clients/`, so it is deliberately out of the S1–S4 scope.

For history findings the remediation is different and the served copy should say so: the secret is
already distributed to every clone, so the action is **rotate**, not edit. The agent must not be led into
proposing a history rewrite.

---

## 6. Testing

- **True-positive corpus** — synthetic secrets per rule, checked in as fixtures, each asserted to fire
  exactly its own rule.
- **False-positive corpus** — the part that decides whether anyone keeps the tool enabled. UUIDs, git
  SHAs, base64 blobs, lockfiles, minified bundles, `.env.example` files, test fixtures. Asserted silent.
- **Fingerprint stability** — same finding across rescans and across unrelated edits to the same file
  keeps its fingerprint; baseline suppression holds.
- **Provenance/staleness** — `no_repo`, `never_scanned`, `artifact_error`, and `ready` states are each
  distinguishable through the MCP surface; a rewritten artifact is served on the next read without a
  server restart.
- **Perf** — benchmark `history` mode against a large real repo; record a wall-clock budget and hold it.
- **MCP conformance** — `resources/list`/`resources/read` round-trip, and confirmation that no MCP
  request path (`get_secret_findings` included) can initiate a scan or write anything.

---

## 7. Open questions

1. **Rule provenance.** ~~Hand-author the initial ruleset, or adapt gitleaks' (MIT)?~~ **Decided:
   hand-author.** The token formats themselves are public knowledge; authoring ~30 rules is cheaper than
   the licensing/attribution review, and the true/false-positive corpus (§6) is what actually guarantees
   quality.
2. **Artifact location.** ~~In-repo vs. the `aac` state dir?~~ **Decided: in-repo**
   (`.bitwarden/secret-findings.json`), gitignored by default. The scanner always excludes its own
   artifact and baseline from scanning, and `aac scan` warns when the artifact path is not gitignored.
3. **Long-term home for the engine.** ~~Starting it here buys a path dep and fast iteration.~~
   **Decided: `sdk-sm` from day one** (crate `bitwarden-scan`). The publishing question dissolves:
   `aac` never consumes the engine — only the artifact JSON, mirrored as a small schema-versioned
   reader module. If a third consumer ever needs the *engine*, publish the crate then.
4. **Desktop surfacing.** Should findings appear in the desktop SM UI? Out of scope here, but if yes it
   requires findings to cross the local wire protocol, which changes §1's clean split. Worth a product
   answer early so S3's artifact shape doesn't have to be redone.
