# Plan — Browser Fill Delivery

**Goal:** Let an agent authenticate a browser session without the credential ever entering the
agent's context — by adding a **browser sink** alongside the existing process-env sink, so
`fill_credential` is to a browser tab what `run_with_credential` is to a child process.

**Core property:** the value never enters the `aac` process at all. `run_with_credential` is
value-bearing — the secret transits `aac` memory (zeroized, scrubbed from captured output, but
present) before reaching the child's environment. A fill request is **value-free end to end on the
`aac` side**: the desktop app resolves the credential and hands it to the browser extension over the
channel it already owns, and replies to `aac` with a status and a `bw://item/<id>` reference. `aac`
is a control channel, not a conduit. That is a strictly stronger property than any tool we ship
today, and it is the sentence the demo is built around.

**Scope:** a third `WireDelivery` variant (`fill`) in local wire protocol v1; the `fill_credential`
and `describe_fill_target` MCP tools and the matching `aac` subcommands in `crates/ap-cli`;
origin-binding and field-safety rules; the desktop and extension work in `bitwarden/clients`
specified here as a binding contract.

**Out of scope:** fill over the relay (remote agent → user's browser) — deferred, see §8; passkey
assertion as a delivery mode — the endgame, and §2 is shaped so it drops in later, but not built
here; any browser automation in this repo. `aac` never drives a browser, exactly as `aac` never
scans (`secret-scanning.md` §1).

> **This plan requires changes to `bitwarden/clients`.** Unlike `secret-scanning.md`, we cannot buy
> cheapness by staying out of that repo: the whole design is that the desktop app keeps the value
> and the extension performs the fill. Most of the risk and most of the effort is on that side.
> §6 is written as a contract for it, and every clients-side claim marked ⚠ is design intent
> inferred from this repo's binding contract, not verified against `clients` — confirm before
> committing to M2.

---

## 1. Architecture

The existing local transport already has the right abstraction and we are adding one value to it.
`WireDelivery` (`transport/local.rs:179`) distinguishes *how* an approved credential comes back:

| Delivery | Reply to `aac` | Value goes to | Shipped |
|----------|----------------|---------------|---------|
| `inject` | `WireCredential` (value-bearing) | child process env, via `aac` | yes |
| `reference` | `WireItem` + `bw://item/<id>` (value-free) | nowhere | yes |
| **`fill`** | **`WireItem` + `bw://item/<id>` + `fill` outcome (value-free)** | **browser tab, via desktop → extension** | **this plan** |

`fill` is closer to `reference` than to `inject` on the wire — the reply carries no secret — but it
has an effect, which `reference` does not. That combination is new and is the whole point.

```
agent ──MCP──▶ aac ──local socket──▶ desktop app ──native messaging──▶ extension ──▶ tab
              (no value)  (no value)   │  resolves vault             │  field-safety invariants
                                        │  approval UI               │  re-verifies origin + plan
                                        └─ value lives only here ────┘
```

**Why the extension, rather than `aac` driving CDP.** Three reasons, in order of weight:

1. **Origin matching and field detection already exist there.** The extension's autofill engine
   matches a vault item's saved URIs against the tab's real origin and knows which input is which.
   Those are the two controls this feature lives or dies on (§3, §4), and reimplementing either in
   Rust against a CDP target would be a strictly worse copy of a thing we already trust in
   production.
2. **No new trust boundary.** The desktop↔extension native messaging channel ships today. We are
   adding message types to an authenticated channel, not building a channel. ⚠
3. **It solves the unlock problem instead of inheriting it.** The naive "let the agent trigger the
   extension's autofill" design requires the *extension's* vault to be unlocked — a per-browser,
   per-timeout human step that fails silently and unattended. Here the desktop app holds the vault
   and the value is **pushed** to the extension for a one-shot fill; the extension needs to be
   installed and connected, not unlocked. The desktop being open and unlocked is already a
   precondition of every agent-access tool, so this adds no new human step at all. ⚠ *This is the
   single most important thing to confirm with the clients team before M2 — if the channel cannot
   carry a one-shot fill payload without the extension's own vault state, the design still works
   but the unlock step returns and the demo gets worse.*

**Layering.** `aac` gains no browser dependency, no CDP client, no DOM knowledge. The extension
gains no vault-query logic. The desktop app remains the only component that holds both a decrypted
value and a user to ask.

---

## 2. Local wire protocol v1 — `delivery: "fill"`

No version bump. Adding an enum variant is forward-compatible in the direction that matters: an old
desktop app receiving `delivery:"fill"` must reject it as an unknown delivery mode rather than
silently degrade to `inject` (which would return a value to a caller that is not expecting one and
has no code path to protect it). Specify that rejection explicitly; do not leave it to serde
defaults.

**Request** — a `credentialRequest` with the new delivery. Note what is *absent*: no tab id, no
origin, no selector. The agent does not name where the fill lands (§3); `targetToken`, when present,
echoes a plan the **extension** produced (§4.4).

```jsonc
{
  "version": 1,
  "type": "credentialRequest",
  "query": {"type": "domain", "value": "bitnotes.io"},
  "delivery": "fill",
  "fill": {
    "fields": ["username", "password", "totp"],  // optional; default all present on the item
    "targetToken": "ft_...",                      // optional; from describeFillTarget, see §4.4
    "submit": false                               // optional; default false, see §5
  },
  "clientInfo": {"name": "aac", "version": "..."}
}
```

**Response** — value-free, shaped like the existing `approved` + `reference` case with one added
object. Per-field outcomes, not a boolean:

```jsonc
{
  "version": 1,
  "status": "approved",
  "item": {"name": "bitnotes.io", "username": "demo@bitnotes.io", "credentialId": "..."},
  "reference": "bw://item/<credentialId>",
  "fill": {
    "status": "filled",                  // filled | partial | no-safe-target | target-changed
                                         //   | origin-changed | extension-unavailable
    "origin": "https://bitnotes.io",     // as reported by the extension, not the caller
    "submitted": false,
    "fields": [
      {"role": "username", "status": "filled",  "target": "input#email (login form)"},
      {"role": "password", "status": "filled",  "target": "input[type=password]#pw"},
      {"role": "totp",     "status": "skipped", "reason": "no one-time-code field on page"}
    ]
  }
}
```

`status: "denied"` and `"timeout"` keep their existing meanings and existing error variants
(`LocalTransportError::Denied`, `::Timeout`). A **new** terminal status is needed for the case that
makes this feature safe:

- `status: "originMismatch"` — the extension's active-tab origin does not match any saved URI on the
  resolved item. The desktop **does not prompt** for this; it refuses. See §3.

New `LocalTransportError` variants `OriginMismatch { origin, item_name }` and `NoSafeTarget
{ reason }`, both constructed without a value like every other variant (`transport/local.rs` module
header).

**Second message type — `describeFillTarget`.** Value-free, vault-free, approval-free (§4.2).
Request `{version, type:"describeFillTarget", clientInfo}`; response carries the page description
and a `targetToken`. It is a peer of `credentialRequest` rather than a delivery mode, because it
resolves no credential and touches no vault.

**Forward hook for passkeys.** `delivery` is an open enum on the wire and the response's effect is
carried in a delivery-named sub-object (`fill`). A future `delivery: "assert"` with an `assert`
outcome object drops in with no reshaping. Do not collapse `fill` into top-level response fields —
that is the change that would make the passkey work expensive later.

**Relay protocol (`protocol-v0.md` §5.1) is untouched by this plan** but should grow an optional
`delivery` field when fill goes remote (§8). Flag it in §5.4 "Open items" now so the two protocols
do not drift.

---

## 3. Origin binding

Everything that makes this feature defensible rather than merely convenient is in this section and
the next. This one keeps the credential from reaching the wrong *site*; §4 keeps it from reaching
the wrong *field*.

**The agent does not choose the target.** The fill lands in the extension's **active tab**, whose
origin the extension reports. The agent supplies a *credential query*; it never supplies a
destination. This deletes the entire class of "agent asks for the bitnotes.io login to be typed into
evil.com" attacks by construction rather than by check — there is no field in which to say
`evil.com`.

The agent is not powerless here — it navigated the tab, so it influences the origin indirectly. That
is fine and is exactly the residual risk the next rule covers:

**Mismatch is a refusal, not a warning.** The desktop compares the extension-reported origin against
the resolved item's saved URIs using the extension's existing match policy. On mismatch it returns
`originMismatch` **without showing the user a prompt**. A prompt would make the control depend on a
human reading a domain carefully at the exact moment an agent has produced a plausible reason to
click through, which is the failure mode phishing is. Refusing mechanically is both safer and a
better thing to show on stage.

**The approval prompt names the origin and the fields.** The user sees "Fill *demo@bitnotes.io*
into **https://bitnotes.io**?" — the origin rendered prominently, from the extension's report, never
from the request — plus the field list from the resolved plan (§4.4), so the prompt describes what
will actually happen rather than what was asked for.

**Approval is per-fill and is not a capability.** The existing rule holds verbatim: a `bw://item/<id>`
reference "is not a capability token" (`transport/local.rs:40`) and redeeming one is a fresh request
with its own approval. A fill is a redemption. Ten fills is ten approvals. Resist the demo-driven
temptation to add a "remember for this origin" checkbox in v1 — if it ships, it ships as an explicit
scoped grant with a visible lifetime, designed on its own, not as a convenience flag bolted onto
this.

---

## 4. Field safety

Two mechanisms, deliberately layered. The extension **refuses to execute an unsafe plan** regardless
of what anyone asked for (§4.1) — that is what actually protects. The agent additionally gets to
**see the plan before it runs** (§4.2) — that is what makes failures debuggable and multi-step
logins possible. Neither substitutes for the other; an agent that skips the preflight still cannot
cause an unsafe fill.

### 4.1 Invariants the extension enforces unconditionally

Enforced at fill time, not merely planned at preflight — the DOM can change in between.

| Role | May only be written to | Never |
|------|------------------------|-------|
| `password` | `<input type="password">` | any visible-text input, under any heuristic, ever |
| `username` | `autocomplete="username"`/`"email"`, or a text/email/tel input in the same form as the password field | a password field |
| `totp` | `autocomplete="one-time-code"`, or a short numeric input | a password field |

The password rule is the one that matters most and it is absolute. A password written into a
`type=text` field is rendered on screen, retained in browser form history, and frequently shipped to
analytics or session-replay — an exposure far worse than the one this whole feature exists to
prevent. No heuristic, no confidence score, no user override.

Additional unconditional refusals:

- **Hidden fields.** Never fill zero-size, `display:none`, `visibility:hidden`, `aria-hidden`, or
  offscreen inputs. Many are honeypot bot-traps whose only purpose is to catch automated filling,
  and a fill nobody can see cannot be verified by anyone.
- **Cross-origin frames.** Never fill inside an iframe whose own origin does not also match the
  item's saved URIs. Otherwise an embedded third-party widget inherits the top-level origin's trust.
- **Registration forms.** A form carrying both a password field and a confirm-password field is a
  signup form; refuse with `looks-like-registration`. Filling one creates an account, which is not
  an autofill outcome and is not what the user approved.
- **Ambiguity.** More than one candidate login form on the page, or more than one candidate field
  for a role, is a refusal (`ambiguous-target`) naming the candidates — never a guess.

Refusals return `no-safe-target` with a machine-readable reason. **Partial fills are allowed in the
safe direction only**: username filled and password skipped is a legitimate `partial` outcome and is
reported per-field; a password filled without a matching username is not a scenario the invariants
can produce.

### 4.2 `describe_fill_target` — the preflight

A read-only description of the active tab, returned to the agent:

```jsonc
{
  "origin": "https://bitnotes.io",
  "formClass": "login",        // login | registration | multi-step-username
                               //   | multi-step-password | none | ambiguous
  "candidates": [
    {"role": "username", "target": "input#email (login form)", "visible": true, "frame": "top"},
    {"role": "password", "target": "input[type=password]#pw",  "visible": true, "frame": "top"}
  ],
  "refusals": [],              // populated with §4.1 reasons when a role has no safe target
  "targetToken": "ft_...",
  "expiresInMs": 30000
}
```

**No approval, no vault access, no value.** It describes the page and nothing else — deliberately
not "which item would be filled," which is `find_logins`' job and carries its own approval. This
matters practically: a preflight that prompts is a preflight agents learn to skip, and the whole
benefit is that calling it is free.

**It discloses nothing new.** The agent driving the browser can already read this structure from the
DOM itself. We are not opening a channel; we are offering the extension's interpretation of a page
the agent can already see — which is strictly more useful than the agent's own guess, because it is
the same interpretation the fill will use.

**It does not reintroduce agent-chosen targets.** The token names a plan *the extension produced*.
The agent can echo it back or discard it; it cannot author one. §3's property is intact.

### 4.3 Multi-step logins

Username on page one, password on page two is now the common case (Google, Microsoft, most SaaS) and
is exactly where a single-shot autofill misfires — there is no password field, so a naive engine
hunts for the closest thing.

The preflight makes it mechanical instead: `formClass: "multi-step-username"` → agent calls
`fill_credential` with `fields: ["username"]`, submits, navigates, preflights again →
`"multi-step-password"` → fills the password. Each step is separately approved and separately
origin-checked. Without the preflight the extension would have to guess whether a password-less page
is step one or a broken page; with it, nobody guesses.

### 4.4 Binding the fill to the plan

`targetToken` binds origin + resolved field plan + a digest of the relevant DOM structure. It is
single-use, tab-bound, and expires in ~30s.

At fill time the extension re-derives the plan and compares. Origin changed → `origin-changed`.
Origin same but the field plan no longer matches → `target-changed`. This extends §3's TOCTOU rule
from *origin* to *origin and plan*: the user approved filling a specific password field on a
specific origin, and if the page has become something else in the intervening seconds — including by
agent action — the fill aborts rather than re-plans against whatever is there now.

**Calling `fill_credential` without a token is supported** and runs the preflight internally,
proceeding only if the result is unambiguous under §4.1. One-call convenience for simple pages, with
identical safety; the token buys the agent visibility and the human a more specific prompt, not a
weaker check.

---

## 5. MCP surface

Seventh and eighth tools, alongside `find_logins` / `run_with_credential` in
`crates/ap-cli/src/command/mcp.rs` (tool list at `:488`, dispatch at `:787`).

```rust
fn fill_credential_tool_def() -> Value {
    json!({
        "name": "fill_credential",
        "description": "Fill a Bitwarden login into the active tab of the user's browser. \
            Requires the Bitwarden desktop app to be open and unlocked, the Bitwarden browser \
            extension to be installed and connected, and the user to approve this request. The \
            credential value is never returned to you and never passes through this tool — the \
            desktop app hands it directly to the browser extension, which fills the form. You \
            cannot choose which tab, origin, or field is filled: the extension fills its active \
            tab, refuses outright if that tab's origin does not match the login's saved URIs, and \
            refuses to write a password anywhere but a password input. Navigate to the login page \
            first, then call this — optionally calling describe_fill_target first to see what \
            would be filled. Provide exactly one of 'domain', 'name', or 'reference'.",
        "inputSchema": { /* domain | name | reference (mutually exclusive, one required),
                            fields?: ["username","password","totp"],
                            target_token?: string, submit?: bool */ },
    })
}

fn describe_fill_target_tool_def() -> Value {
    json!({
        "name": "describe_fill_target",
        "description": "Describe the login form in the active tab of the user's browser: its \
            origin, which fields would be filled for which role, and why any field would be \
            skipped. Returns no vault data and no credential values, and requires no approval. \
            Use it before fill_credential to check the page is what you expect, and to handle \
            multi-step logins where the username and password are on separate pages. Returns a \
            target_token that fill_credential accepts to guarantee it fills exactly the plan \
            described here.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": false},
    })
}
```

Three details worth deciding deliberately rather than discovering:

- **`submit` defaults to `false`.** The tool fills; the agent clicks. Keeping the click on the
  agent's side means the browser MCP's own tooling produces the navigation, which keeps the
  post-login state legible to the agent and keeps `fill_credential` from owning page semantics it
  cannot see. Offer `submit: true` because some flows need same-gesture submission, but do not
  default to it.
- **The descriptions are a security control.** They state the constraints the agent will otherwise
  try to route around — this is precisely the tool whose absence caused a model to read a password
  out of a README. Say plainly that the value is unavailable, that no workaround exists, and what to
  do instead (navigate, preflight, fill). An agent that understands the boundary stops probing it.
- **Errors are actionable and value-free.** `origin-mismatch` names the tab origin and the item;
  `no-safe-target` names the reason (`looks-like-registration`, `ambiguous-target`,
  `no-password-field`, `hidden-field-only`, `cross-origin-frame`); `extension-unavailable` says the
  extension is not connected to the desktop app. Never echo a value, per the module contract.

`aac fill [--domain <d> | --name <n> | --ref bw://item/<id>] [--fields ...] [--submit]` and
`aac describe-fill-target` mirror the tools, for humans and for the QA harness. Same code path, same
approval.

---

## 6. Desktop and extension contract (`bitwarden/clients`) ⚠

Specified here as the binding contract; owned there.

**Desktop endpoint.** Accept `delivery: "fill"` on `credentialRequest` and the new
`describeFillTarget` message. Resolve the query as today. Ask the extension for its active-tab origin
*and resolved field plan* before prompting — both are inputs to the refusal checks and to the prompt
text. On origin mismatch return `originMismatch` with no prompt; on §4.1 refusal return
`no-safe-target` with no prompt. On match, prompt with item + origin + field plan. On approval, send
the fill payload and await the result. The value must not be written to any log, IPC trace, or crash
report on this path.

**Native messaging: two new message types, desktop → extension.**
`describeTarget {}` → the §4.2 description. `fill {origin, targetToken?, fields, submit,
credential:{username?, password?, totp?}}` → one immediate fill, replying with per-field outcomes.
The extension holds the credential only for the duration of the fill and does not persist it to its
vault state, its cache, or its "last filled" history.

**Extension handler.** Re-verify origin and re-derive the field plan (§4.4). Enforce §4.1
unconditionally — these checks live in the extension, not the desktop, because only the extension
can see the DOM at the moment of writing. Run the existing autofill engine for element selection,
then apply the invariants as a gate on its output rather than trusting its ranking.

**Approval UI.** New prompt variant. The origin is the visually dominant element, with the field plan
beneath it. Reuse the existing 60s approval timeout so the client's 120s read timeout continues to
bound the round trip (`transport/local.rs:30`).

---

## 7. Threat model — state it before someone else does

This feature makes the credential **absent from the model's context and absent from `aac`**. It does
not make the credential unreadable by the agent afterwards: once filled, an agent holding arbitrary
JS evaluation on that page can read `document.querySelector('input[type=password]').value`. That is
a property of browsers, and no fill mechanism — ours, a human's, or a password manager's — changes
it.

Say this plainly in the tool description, the docs, and the demo. The README already sets the honest
frame ("we do not recommend inputting sensitive credentials directly into LLMs"), and the value
delivered is real and worth stating precisely:

- the value never appears in recorded model context, transcripts, or telemetry;
- the value never enters the `aac` process;
- every use is individually approved by a human, bound to an origin and a field plan the human sees;
- an agent cannot direct a credential to an origin the item does not claim, or into a field that
  would render it visible.

What remains uncovered is *post-fill exfiltration by an agent with page-level code execution*. Two
mitigations, one operational and one architectural:

- **Operational (document now):** an agent granted `fill_credential` should not also hold arbitrary
  script evaluation on the same origin. This belongs in the deployment guidance next to the tool,
  not in code.
- **Architectural (the actual answer):** passkeys. A WebAuthn assertion is origin-bound and
  non-replayable — there is nothing in the DOM to read back and a captured assertion is worth
  nothing. For a password manager answering "how should agents authenticate," *stop shipping
  replayable secrets to the page* is a stronger position than any amount of careful password
  plumbing, and it is one only a vault can offer. §2's delivery-mode shape exists so that work is
  additive.

---

## 8. Milestones

**M1 — protocol + `aac` (this repo only).** `WireDelivery::Fill`, the `describeFillTarget` message,
fill request/response types with per-field outcomes, `OriginMismatch` and `NoSafeTarget` error
variants, both MCP tools, both CLI subcommands. Tested against a mock endpoint in the style of the
existing wire round-trip tests (`transport/local.rs:874+`): approved-filled, partial, denied,
timeout, origin-mismatch, each §4.1 refusal reason, target-changed, origin-changed,
extension-unavailable, and an unknown-delivery rejection. Ships behind no flag because it is inert
until M2 exists — an old desktop returns an unknown-delivery error, which is the correct behavior.

**M2 — desktop endpoint + approval UI (`clients`).** Gated on confirming the §1.3 unlock assumption
first. Fill can be stubbed at the extension boundary; M2 is done when the prompt shows a real origin
and a real field plan, and both refusal paths return without prompting.

**M3 — extension handlers (`clients`).** Native messaging types, the §4.1 invariants, preflight
description, origin and plan re-verification, TOTP, one-shot payload handling with no persistence.
The invariants land in M3 with their own unit tests against fixture pages — honeypot fields,
registration forms, multi-step flows, cross-origin iframes, dual login/signup pages.

**M4 — demo + docs.** §9. Tool-description review as a security review. Deployment guidance from §7.

**Deferred, deliberately:**
- *Fill over the relay.* A remote agent filling a browser on the user's machine is coherent and
  compelling, and needs `delivery` added to `protocol-v0.md` §5.1 plus a decision about whether the
  origin display is trustworthy when the requester is remote. Note it in §5.4 Open items now.
- *Scoped re-fill grants* (§3).
- *Passkey assertion delivery* (§7).

---

## 9. Demo script

The order matters. The refusals are the product, so they go last and they go unedited.

1. Agent navigates to the bitnotes.io login page with the browser MCP.
2. Agent calls `find_logins` → sees `demo@bitnotes.io` exists, with **no password**, as today.
3. Agent calls `describe_fill_target` → shows the form it found and the fields it would fill. The
   agent is reasoning about a real page, not guessing.
4. Agent calls `fill_credential`. Desktop prompts: *Fill demo@bitnotes.io into
   **https://bitnotes.io** — username and password?* Approve. Form fills, agent clicks Submit,
   session established.
5. Show the transcript. The password is not in it. Show that `aac` never held it either — this is
   the beat that distinguishes fill from `run_with_credential`.
6. **The refusals.** Same credential on a lookalike origin: no prompt, `origin-mismatch`. Then the
   same credential on a page whose only password-shaped input is a visible text field: no prompt,
   `no-safe-target`. Nobody had to notice anything either time.

Step 6 is the answer to "why does this need a password manager rather than a config file," and it is
the step to rehearse until it is boring.

---

## 10. Open questions

1. **Can the native messaging channel carry a one-shot fill payload without the extension's own vault
   being unlocked?** (§1.3.) Blocks M2 scoping. If no, the design survives but requires an extension
   unlock step and the "no new human step" claim comes out of the demo.
2. **Whose URI-match policy?** Reusing the extension's existing matching is the whole argument in
   §1.1, but the *refusal* decision is made desktop-side. Either the desktop calls into the same
   match implementation or the extension returns a match verdict alongside the origin. Prefer the
   latter — one implementation, and the component that knows the tab decides. The same question
   applies to the §4.1 field verdicts, with the same answer.
3. **How much does the existing autofill engine already refuse?** §4.1 is written as a gate applied
   *on top of* the engine's element ranking, on the assumption that the engine ranks rather than
   refuses. If it already enforces some of these, adopt its implementation rather than duplicating;
   if it deliberately fills visible-text fields in some legacy compatibility case, that case must be
   excluded from agent fills even if it stays for human ones — a human sees what got filled, an
   agent's user does not.
4. **Multiple matching items for a domain.** `find_logins` can disambiguate first, but a bare
   `domain` query that resolves to several items needs a rule. Proposal: refuse with an ambiguity
   error naming the candidates by reference, matching how `run_with_credential`'s name-query
   ambiguity behaves; never guess.
5. **Non-active-tab fills.** Deliberately unsupported in v1 (§3). Revisit only with a concrete flow
   that active-tab genuinely cannot serve.
6. **Does `submit: true` belong in v1 at all?** It is the one parameter that hands page semantics to
   a component that cannot see the page. Cheap to add later; awkward to remove.

---

## 11. Resolutions (2026-08-11, implemented)

M1–M3 are built (this repo + `bitwarden/clients` + a 3-line server mirror). The binding contract
lives in `clients` at `apps/desktop/src/agent-access/agent-access-architecture.md` §M5 — where it
differs from this plan, §M5 wins. Deltas: the wire op field is `op` (not `type`) and client info
serializes as `client` (not `clientInfo`); `submit` is cut from v1 (Q6 = no); origin verdict is
computed desktop-side via the shared `LoginUriView.matchesUri` with extension string-equality
re-verification at fill time (Q2); multiple matching items origin-filter into the existing picker
instead of refusing (Q4); MCP `name` maps to the wire `search` query. Q1 answered yes: no unlock
step — the desktop↔extension leg rides SDK IPC JSON topics (topic `agent-fill`), whose handshake
is vault-free. Q3 answered: the existing engine ranks rather than refuses (content-side fill has
no input-type check, and `isLikePasswordField` fills visible text inputs named "password"), so
agent fills use a new §4.1-constrained planner + write-time re-checks and never reuse
`generateLoginFillScript`.
