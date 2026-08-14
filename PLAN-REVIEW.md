# Plan-Review: Agent Operational-Radius Disclosure for the Pi Sandbox Extension

Review of an initiative to enhance the Pi Sandbox extension by implementing a
whitelist of paths that restricts the agent's operational radius — analyzing
bash-tool arguments, identifying embedded paths, preventing non-adherent
commands, and providing the agent with a clear display of the allowed paths.

## Verdict

**Feasible: YES. Logical: YES, *after reframing*.** The initiative as
originally worded ("implement a whitelist of paths… analyze bash arguments,
identify embedded paths, prevent non-adherent commands") describes a mechanism
that is **~90% already shipped** in this extension. The genuine delta — and the
part worth building — is **proactive disclosure of the operational radius to
the agent** (point 4 of the objective), so the agent self-orients instead of
learning the radius reactively through block reasons.

Two pieces of news from the codebase make the reframing non-negotiable:

1. **Enforcement exists and is tested.** `paths.allow`/`paths.deny` +
   `extractPathTokens()` + `evaluateBash()` + the `tool_call` block path already
   do "prevent non-adherent commands." Rebuilding them rewrites tested code and
   reopens a threat model the author *chose*.
2. **Disclosure is genuinely feasible on a sanctioned API.** `before_agent_start`
   hands the handler the assembled `systemPrompt` and accepts a `systemPrompt`
   override each turn (verified in
   `@earendil-works/pi-coding-agent/.../agent-session.js:881–905`). It fires in
   all modes (interactive, RPC, print).

So the initiative should be scoped as: **a per-turn, always-fresh
radius-disclosure block injected into the system prompt, projecting existing
policy — no new enforcement, no new config.**

## What's already implemented (do not rebuild)

| Objective clause | Existing implementation |
|---|---|
| Whitelist of paths / operational radius | `paths.allow` (default `["./**"]`), `paths.deny`, evaluated for file tools *and* bash tokens |
| Analyze bash args, identify embedded paths | `extractPathTokens()` (`paths.ts`), run on every segment after proxy unwrapping |
| Prevent non-adherent commands | `evaluateBash()` deny/ask verdicts → `index.ts` `tool_call` block |
| Show agent the allowed paths *(reactive only)* | block/ask reasons cite the offending path + matched pattern; `/sandbox list` dumps to the **UI**, not reliably to agent context |

The last row is the gap this initiative closes.

## Resolved design (decision tree, with rationale)

| # | Decision | Choice | Key reason |
|---|---|---|---|
| Q1 | Framing | **Disclosure, not enforcement** | Enforcement exists & is tested; rebuild reopens the threat model |
| Q3 | Disclosure surface | **`before_agent_start` system-prompt append** | Per-turn, fresh, works in non-interactive modes |
| Q4 | Granularity | **Paths only** (`allow` + `deny`); commands/tools/bwrap excluded | Stays on-mission ("radius"); smallest, most cache-stable |
| Q5 | Pattern form | **Raw globs + a constant gloss sentence** | Patterns match block-reason strings verbatim; gloss is cache-stable insurance |
| Q6 | Mode awareness | **Active negated block when OFF** | `--no-sandbox` postdates any baked guidance; only a per-turn block can correct it |
| Q7 | Channel | **Single channel (a); drop (b)** | (b) `promptGuidelines` only registers when `bwrap.enabled` — coverage hole; cache is neutral, so (b) is redundant |
| Q8 | bwrap footprint | **One conditional line** when `bwrapActive && autoAllow` | Explains the bash-vs-file ask asymmetry the agent will *observe* |
| Q9 | cwd anchor | **Resolve `./**`→`<abs-cwd>/**` for display, per turn** | Removes the ambiguity the initiative exists to fix; engine and guidance cite identical strings |
| Q10 | Deny provenance | **Flat merged + "unbypassable" header** | Preempts the highest-impact agent misbehavior (pestering the user / probing workarounds) |
| Q11 | Snapshot | **Accept turn-snapshot, no note** | Enforcement is live every `tool_call`; lag is one-directional (under-disclosure), never a safety issue |
| Q12 | Extraction gap | **Disclose only; defer hardening** to a separate issue | Keeps the accepted guardrail threat model; `--flag=PATH` bypass is real but out of scope |
| Q13 | Config surface | **Zero-config, always-on** | Matches the "config = policy" invariant; no new presentation knob |
| Q14 | Verbosity | **Compact**: one dense header + capped denies | ~150 vs ~400 tokens; better cache stability; deterministic truncation |
| Q15 | Module | **New `disclosure.ts`** | One pure function; unit-testable; `index.ts` stays wiring-only |

## Defects surfaced & resolved during review

1. **Framing defect (Q1).** Pitching this as building path whitelisting would
   duplicate shipped, tested code. Resolved: scoped to disclosure.
2. **Cache-coherence defect (Q3→Q3′→Q7).** The "stable block in
   `promptGuidelines`, delta in `before_agent_start`" split would have gone
   *stale after every mid-turn autosave* (`promptGuidelines` is read only at
   session-start / `/reload`). Then `promptGuidelines` was found to **only
   register when `bwrap.enabled`** — a coverage hole in the common no-bwrap
   config. Resolved: collapse to a single per-turn `before_agent_start`
   channel.
3. **`--no-sandbox` temporal defect (Q6).** A signpost baked at `session_start`
   cannot know a per-invocation `--no-sandbox` passed later. Resolved: per-turn
   negated block is the authoritative mode signal.
4. **Deny pestering defect (Q10).** Flat denies alone invite the agent to argue
   provenance ("it's only a project deny"). Resolved: unbypassable header.
5. **Extraction-bypass vs. claim defect (Q12).** "Preventing non-adherent
   commands" is literally false for `--flag=PATH` and quoted/substitution forms.
   Resolved by honest scoping: disclose only; file extraction hardening as a
   follow-up issue, not part of this initiative.

## Spec: the radius block

Consumed each turn by `before_agent_start` as a system-prompt **append**
(preserving any prior extension's `systemPrompt`):

```
Operational radius — obey it. `*` = one path segment, `**` = any depth,
`~/` = home, `./` = <resolved project root>. Denies are unbypassable;
do not ask the user to lift them or seek workarounds.

Operate within:
  /home/deplague/.pi/agent/extensions/sandbox/**
  ~/Projects/**
Do not touch:
  **/.env, **/.env.*, **/.git/**, **/.ssh/**, **/id_rsa*, **/*.pem
  **/*.jks, **/secrets/**, **/application-prod.yml
  (+2 more from global config; run /sandbox list)
[Bash is kernel-sandboxed with auto-allow; unlisted bash path tokens may run
without prompting, bounded by the sandbox.]
```

- Header is one **constant** sentence (cache-stable; folds mode-hedge + gloss +
  unbypassable per Q14).
- `mode === "off"` **or** `--no-sandbox` → replace the whole block with:
  *"Sandbox is OFF — no radius is in force; operate freely."*
- Allows: cwd-anchored patterns resolved to absolute (Q9); raw globs
  otherwise (Q5).
- Denies: flat merged, raw globs; deterministic cap — built-in defaults always,
  then global, then project, truncating **project fills last** with
  `"+N more"` (Q14). Order is fixed so truncation is content-deterministic.
- Footnote (last line) only when `bwrapActive && autoAllow` (Q8).

## Implementation outline

```
disclosure.ts  (new, pure)
  export function renderRadiusBlock(state: PolicyState): string
    // state = { config: SandboxConfig, cwd, disabled, onceCache, bwrap: {active, autoAllow} }
    // 1. disabled || mode==='off'  -> negated block (return early)
    // 2. header: constant combined sentence
    // 3. allows: map paths.allow -> resolve cwd-anchored (./**, ./...) to
    //           path.resolve(cwd,...) for display; keep **/, ~/, absolute as-is
    // 4. denies: flat merge of effective.paths.deny (already merged in config),
    //           deterministic partition (built-in / global / project) for cap
    // 5. footnote: only if bwrap.active && config.bwrap.autoAllow

index.ts  (modify)
  pi.on("before_agent_start", (event, ctx) => {
    const text = renderRadiusBlock(stateFor(ctx));
    return { systemPrompt: event.systemPrompt + "\n\n" + text };
  })
  // stateFor() already returns {config, cwd, disabled, onceCache, bwrap}
  // ensureLoaded()/bwrapActive set by session_start, which fires before any turn
```

- **No `config.ts` changes** (Q13/A). **No new bash-tool registration** (Q7/λ).
- Cache correctness (Q2): the block must be a **pure function** of
  `(effective config, cwd, bwrapActive, disabled)` — no timestamps, no
  `onceCache`, no counts. Rendering patterns verbatim (not summaries) keeps it
  content-stable across autosaves of *other* sections.
- Chaining safety (verified `agent-session.js:898`): return the **full**
  `event.systemPrompt + append`, never just the delta — replace semantics; we
  must preserve sibling extensions' contributions.

## Risks & caveats

- **Snapshot lag (Q11).** After a mid-turn "Always allow", enforcement is live
  immediately; the advisory block updates next turn. Harmless (under-disclosure
  only). Documented as accepted.
- **Sibling extension ordering.** If another extension also returns
  `systemPrompt`, pi chains them. Our block is small (Q14), so even if a
  volatile sibling sits before us and pushes our block into the uncached tail,
  the per-turn cost is bounded (~150 tokens).
- **Extraction bypass remains (Q12).** `--flag=PATH`, quoted paths,
  substitutions are not caught — the accepted guardrail threat model. The
  initiative's "prevent non-adherent commands" claim should be **honestly
  qualified** in the README as "guided + best-effort enforced," not
  "guaranteed."
- **Determinism for cache.** Any non-determinism in `renderRadiusBlock`
  (e.g. relying on `fs.realpathSync` of the anchor each turn — a symlink flip
  would change the displayed string) introduces churn. Resolve the anchor via
  `path.resolve(cwd)` (stable) rather than `realpath` (volatile) **for the allow
  display** — a deliberate divergence from `normalizePath`'s realpath behavior,
  justified because disclosure needs stability whereas enforcement needs
  canonicalization.

## Recommended follow-ups (separate issues, not this initiative)

1. **Bash path-extraction hardening** — at least the `--flag=PATH` split
   (Q12/ψ+). This is the one place "preventing non-adherent commands" is
   materially untrue; closing it makes the README claim defensible. Out of scope
   here only for threat-model discipline.
2. **Optional queryable `sandbox_radius` tool** (Q2 option c) — a supplement for
   agents that want to *re-fetch* the radius after an autosave mid-turn,
   eliminating the snapshot lag for the cost of one tool call. Deferred; the
   per-turn block covers the common case.

## Feasibility checklist

- [x] pi exposes a per-turn system-prompt override hook (`before_agent_start`)
- [x] Hook fires in interactive, RPC, and print modes (not gated on `ctx.hasUI`)
- [x] Effective config + bwrap state already computed by existing
      `stateFor()`/`ensureLoaded()`
- [x] No new dependencies; no new config schema; no new bash override
- [x] Pure renderer is unit-testable in isolation
- [x] Cache stability is achievable by the content rules above

---

**Bottom line:** The initiative is feasible and becomes logical once reframed
from "build path whitelisting" to "disclose the existing radius to the agent's
context each turn." It is a small, additive, zero-config change: one new pure
module (`disclosure.ts`) and one new `before_agent_start` handler in `index.ts`.
The review's value was mostly in *not* rebuilding existing enforcement and in
catching three coherence defects (the `promptGuidelines` coverage hole, the
`--no-sandbox` temporal defect, and the autosave snapshot lag) that would have
shipped as subtle bugs under the naïve design.