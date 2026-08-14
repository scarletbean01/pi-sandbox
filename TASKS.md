# TASKS — Operational-Radius Disclosure

Implementation tasks for the disclosure initiative reviewed in
[`PLAN-REVIEW.md`](PLAN-REVIEW.md). Scope: **disclosure only** — no enforcement
rebuild, no new config, no new bash-tool registration. A single pure module
(`disclosure.ts`) plus one `before_agent_start` handler in `index.ts`.

Decision tags refer to the question numbers in PLAN-REVIEW.md.

---

## 1. Prerequisites / verification

- [ ] 1.1 Re-confirm `before_agent_start` event shape in
      `@earendil-works/pi-coding-agent`: handler receives
      `{ systemPrompt: string, systemPromptOptions, prompt, images? }` and may
      return `{ systemPrompt?: string, message?: ... }`. Verify the returned
      `systemPrompt` *replaces* (and is chained) by reading
      `core/extensions/types.d.ts` + `core/agent-session.js` `emitBeforeAgentStart`.
- [ ] 1.2 Re-confirm `stateFor(ctx)` returns everything the renderer needs:
      `{ config: SandboxConfig, cwd, disabled, onceCache, bwrap }` with
      `bwrap: { active, autoAllow }`. If `PolicyState` needs a field it lacks,
      extend `policy.ts` **type-only** (no logic change).
- [ ] 1.3 Re-confirm `evaluate()` short-circuits to `allow` on
      `state.disabled || config.mode === "off"` — the renderer must use the
      *same* predicate so the negated block (Q6) is consistent with enforcement.
- [ ] 1.4 Re-confirm pi places the prompt-cache `cache_control` marker at the
      *end* of the (replaced) system prompt, so an appended block rides the
      stable cached head and only the changing tail misses. (No code change;
      informs the cache-stability acceptance criteria in §6.)

## 2. `disclosure.ts` — pure renderer (new module)

Model: one pure function. Pure with respect to `(state.config, state.cwd,
state.disabled, state.bwrap.active, state.bwrap.autoAllow)` — **no** filesystem
`realpath`, **no** timestamps, **no** `onceCache`, **no** counts in output.

- [ ] 2.1 Create `disclosure.ts`. Export `renderRadiusBlock(state: PolicyState):
      string`. Import only types/values: `PolicyState` from `./policy`,
      `expandTilde` (or inline a copy) for `~/`. **Do not** mutate `state`.
- [ ] 2.2 **Off-mode branch (Q6/θ).** If `state.disabled` **or**
      `state.config.mode === "off"`, return exactly:
      `"Sandbox is OFF — no radius is in force; operate freely."`
      (constant string; no further content). This is the single authoritative
      mode signal that corrects any stale `session_start` signpost under
      `--no-sandbox`.
- [ ] 2.3 **Header (Q14/Q — one constant sentence).** Append a fixed, literal
      header string folding mode-hedge + glob-gloss + unbypassable:
      `Operational radius — obey it. \`*\` = one path segment, \`**\` = any depth, \`~/\` = home, \`./\` = <project root>. Denies are unbypassable; do not ask the user to lift them or seek workarounds.`
      Never computed/templated beyond substituting the resolved project root
      label (Q9) — keep it a literal so it is byte-identical every turn.
- [ ] 2.4 **Allow rendering (Q5/ζ, Q9/π).** For each pattern in
      `state.config.paths.allow`:
  - If it starts with `./` or `.`/relative-segment → display as
    `path.resolve(state.cwd, expandTilde(p))` (stable resolution, **not**
    `realpath` — see PLAN-REVIEW Risks). Strip the trailing `/./`/redundant
    separators.
  - Else (`**/…`, `~/…`, absolute) → display verbatim.
  - Dedup, preserve config order. Emit under a heading line `"Operate within:"`.
- [ ] 2.5 **Deny rendering (Q5, Q10/τ, Q14/Q).** For each pattern in
      `state.config.paths.deny` (already merged across defaults/global/project
      in `config.ts`): display verbatim (no anchor resolution; denies are
      glob-stated). Apply **deterministic capping**:
  - Partition the merged deny list into `[built-in defaults] ++ [global] ++
    [project]` by re-deriving membership from `DEFAULT_CONFIG.paths.deny`
    (built-in) and the *loaded* global/project sources. (See task 2.7 for the
    provenance plumbing.)
  - Always render all built-in defaults.
  - Then render global denies.
  - Then render project denies until the cap (`MAX_DENIES_SHOWN`, default 12
    total) is reached; if project denies overflow, render the cap and append
    `"(+N more from project/global config; run /sandbox list)"` with the exact
    remaining count.
  - Truncate **project fills last** so the truncation is content-deterministic.
  - Emit under a heading line `"Do not touch:"`.
- [ ] 2.6 **Footnote (Q8/ν).** Append the autoAllow footnote **only** when
      `state.bwrap?.active && state.config.bwrap.autoAllow`:
      `"[Bash is kernel-sandboxed with auto-allow; unlisted bash path tokens may run without prompting, bounded by the sandbox.]"`
      Constant string; one line; bracketed. Omit entirely otherwise (so the
      block is byte-identical across turns when the state is unchanged).
- [ ] 2.7 **Provenance sourcing for capping (Q14).** The merged deny list alone
      (`config.paths.deny`) loses provenance. To truncate *project fills last*
      you need masks per layer:
  - Add an exported helper in `config.ts`: `denyProvenance(loaded):
      { builtin: string[]; global: string[]; project: string[] }` computed from
      `DEFAULT_CONFIG.paths.deny`, the loaded `globalParsed.paths.deny`, and
      `projectParsed.paths.deny`. (No change to `SandboxConfig`; additive
      helper only.)
  - OR: thread the three arrays into `renderRadiusBlock` via a small
      `RadiusSources` struct built once in `index.ts` at load time.
  - Pick whichever touches `config.ts` least; prefer the helper to keep
    `index.ts` wiring-only.
- [ ] 2.8 **Determinism audit.** Confirm output depends only on documented
      inputs. In particular: no `fs.realpathSync`, no `process.hrtime`/Date,
      no `Set` iteration over insertion-order-dependent structures that could
      vary across reloads. (Maps preserve insertion order in V8 — that's fine
      *if* the insertion order is itself deterministic from config load.)
- [ ] 2.9 **Empty-config handling.** When `paths.allow` would render only the
      default `./**`, still render it (resolved). When `paths.deny` is empty
      besides defaults (rare — defaults are always present), still render
      `"Do not touch:\n  (built-in defaults: …)"`. No empty headings.
- [ ] 2.10 **Typecheck.** `npx tsc --noEmit` passes (strict,
       `erasableSyntaxOnly`).

## 3. `index.ts` — wiring the hook

- [ ] 3.1 Register `pi.on("before_agent_start", handler)` near the other
      `pi.on(...)` registrations. Handler signature:
      `(event: BeforeAgentStartEvent, ctx: ExtensionContext) =>
      { systemPrompt: string } | undefined`.
- [ ] 3.2 Inside the handler:
  - Compute `renderRadiusBlock(stateFor(ctx))`.
  - If the result is non-empty, return
    `{ systemPrompt: event.systemPrompt + "\n\n" + text }`.
    **Always concatenate onto the full `event.systemPrompt`** (chaining:
    preserve sibling extensions' contributions — replace semantics, Q +
    agent-session.js:898).
  - Else return `undefined` (leave the prompt untouched).
- [ ] 3.3 Ensure `stateFor(ctx)` reflects the current `disabled` (it already
      reads `pi.getFlag("no-sandbox")`) and current `bwrapActive` (session-scoped
      module var, already set by `session_start` before any turn). No new state.
- [ ] 3.4 **Re-render on `/sandbox on|off`.** The existing `/sandbox on|off`
      handler mutates `current.effective.mode` and calls `updateStatus`. Because
      `before_agent_start` re-renders **every turn** from `stateFor`, no explicit
      raid is needed — but verify the next turn reflects the new mode before the
      user's next prompt is sent. (No code change expected; document the
      turn-snapshot in §4 if a user could be confused.)
- [ ] 3.5 **Re-render after autosaves.** `persistAllow` mutates
      `current.effective.*.allow` in place; the next `before_agent_start` will
      pick up the change. No explicit re-render is added (Q11/φ: accept one-turn
      lag in the *advisory* block; enforcement is already live). Confirm no code
      is needed; if the resolved-allow anchor depends on `ensureLoaded()` cwd
      and cwd is constant per session, this is automatic.
- [ ] 3.6 Typecheck passes.

## 4. `/sandbox status` & `/sandbox list` parity (optional disclosure pointers)

- [ ] 4.1 In the `/sandbox status` notify, add a one-line note that the radius
      is also disclosed to the agent each turn via the system prompt (so a user
      inspecting status knows the agent is *informed*, not just gated). Keep it
      to one short line; this is user-facing, not agent-facing.
- [ ] 4.2 In `/sandbox list`'s dumped policy, no change is required — it already
      lists `paths.allow`/`paths.deny`. Leave it (the `(+N more … run /sandbox
      list)` footnote in the block points here for the truncated deny tail).

## 5. README updates

- [ ] 5.1 Add a short **"Radius disclosure to the agent"** subsection under
      "How it works": describe that an "Operational radius" block is appended
      to the system prompt each turn, what it contains (allows + denies +
      optional footnote), and the off-mode negated line.
- [ ] 5.2 State the **snapshot semantics** honestly: advisory block is a
      turn-snapshot; enforcement is live every tool call; newly-autosaved
      allows appear next turn.
- [ ] 5.3 **Honesty clause for the objective** (Q12): qualify "preventing
      non-adherent commands" as **best-effort enforced + guided**, not
      guaranteed — link to the existing "guardrails, not a security boundary"
      threat-model paragraph and note `--flag=PATH` / quoted paths /
      substitutions as known heuristic gaps (existing caveat; no new threat
      model).
- [ ] 5.4 In **"Notes for AI agents"**, add a bullet: the "Operational radius"
      block in the system prompt is authoritative for *where* you may operate;
      obey it; denies are unbypassable — do not pester the user or seek
      workarounds (ties into the existing "a block reason is final" guidance).
- [ ] 5.5 Leave the **full config reference** unchanged (Q13/A: no new config
      key). Optionally add a one-line note next to the `mode` description that
      the off-mode silences *and* switches the disclosed block to the negated
      line.

## 6. Verification / acceptance

### 6.1 Unit assertions (renderer, no pi needed)
- [ ] 6.1.1 Off-mode (`mode: "off"` OR `disabled: true`) → exact negated string.
- [ ] 6.1.2 `mode: "enforce"`, default config → header line present; allow line
      is the resolved `<cwd>/**`; all built-in denies present; no footnote.
- [ ] 6.1.3 `./foo/**` → rendered as `<cwd>/foo/**`; `~/Projects/**` verbatim;
      `**/.env` verbatim; absolute `/etc/**` verbatim.
- [ ] 6.1.4 Deny capping: with built-ins (6) + global (4) + project (10),
      total rendered = 12 with `"(+8 more …)"`; truncation hits **project**
      denies, never built-in; count in suffix matches remaining exactly.
- [ ] 6.1.5 Footnote present iff `bwrap.active && config.bwrap.autoAllow`;
      absent when either is false. Block is otherwise identical to 6.1.2.
- [ ] 6.1.6 **Cache-determinism check**: call `renderRadiusBlock` twice with
      identical `state` → identical strings (byte-equal). Vary only an unrelated
      config field (e.g. `commands.allow` grows by one) → block string
      unchanged.
- [ ] 6.1.7 Anchor uses `path.resolve` (stable), not `realpath` — assert no
      `fs` import in `disclosure.ts` (the renderer must be FS-free).
- [ ] 6.1.8 No counts/timestamps in output: regex the rendered strings for
      forbidden tokens (`new Date`, `\d{4}-`, etc. — should be none beyond the
      `+N more` count, which is derived from a length, not wall-clock).

### 6.2 Type & build
- [ ] 6.2.1 `npx tsc --noEmit` clean (strict, `erasableSyntaxOnly`).
- [ ] 6.2.2 No new dependencies in `package.json`.

### 6.3 Live (tmux / `pi`) — manual matrix
- [ ] 6.3.1 Fresh session in the extension's own dir → first user turn's system
      prompt (inspect via a debug `pi.sendMessage` or `ctx.ui.notify` in the
      handler during dev) contains the "Operational radius" block with the
      resolved cwd in the allow line.
- [ ] 6.3.2 `/sandbox off` → next turn's block is the negated line; agent is
      unblocked (enforcement off). `/sandbox on` → block returns to full.
- [ ] 6.3.3 `pi --no-sandbox` → from the first turn, the block is the negated
      line **and** enforcement is off (the per-turn block is the authoritative
      mode signal, correcting any stale session-start signpost — Q6).
- [ ] 6.3.4 Trigger an autosave mid-turn ("Always allow <path>") → the
      *current* turn's block still reflects the pre-autosave radius; the
      *next* turn's block reflects the new allow line (Q11 snapshot). Confirm
      enforcement was live immediately (the `read`/`bash` call that prompted
      the ask succeeds after the choice).
- [ ] 6.3.5 With bwrap enabled + `autoAllow: true` → footnote present. With
      `autoAllow: false` → footnote absent. With bwrap disabled/unavailable
      (`bwrap.active` false) → footnote absent even if `autoAllow: true`.
- [ ] 6.3.6 Non-interactive: `pi -p "<prompt>"` → handler still fires (verified
      in SDK; `before_agent_start` is not gated on `ctx.hasUI`) and the block is
      appended; behavior matches interactive. (The existing `/sandbox list` UI
      dump does not run here, so the block is the *only* disclosure surface —
      this is the core gap the initiative closes.)
- [ ] 6.3.7 Chaining: if a second extension appends to the system prompt, the
      sandbox block still appears (we concatenate onto `event.systemPrompt`).
      Check with a dummy scratch extension returning `systemPrompt`, confirm
      both contributions survive.
- [ ] 6.3.8 `/reload` after hand-editing config → next turn's block reflects the
      edited allows/denies (re-probe + `loaded = undefined` already happens on
      `session_start`; confirm `/reload` path triggers it).

### 6.4 Regression (existing behavior unchanged)
- [ ] 6.4.1 Existing `/sandbox on|off|status|list` behavior unchanged (block is
      additive; status/list untouched except optional §4.1 note).
- [ ] 6.4.2 Existing enforcement matrix unaffected: blocked command still
      blocked with the same reason; path denies still block; `--no-sandbox`
      still bypasses.
- [ ] 6.4.3 Footer status string unchanged.
- [ ] 6.4.4 `user_bash` (`!`/`!!`) still exempt from enforcement; the radius
      block is *advisory* and appears in the system prompt regardless (it does
      not gate `user_bash`).

## 7. Out-of-scope (do NOT do in this initiative)

- ❌ Rebuilding path whitelisting / bash path extraction / enforcement (Q1).
- ❌ Hardening `extractPathTokens` for `--flag=PATH` or quoted paths (Q12 →
      file as a separate follow-up issue; do not scope-creep here).
- ❌ New config key / opt-out toggle (Q13/A).
- ❌ `promptGuidelines` signpost channel (Q7/λ — collapsed into the per-turn
      block).
- ❌ Mid-turn refresh of the block via `before_provider_request` (Q11/χ — cache
      churn; snapshot accepted).
- ❌ Provenance-grouped deny display (Q10/υ — invites pestering; flat + header
      only).
- ❌ Queryable `sandbox_radius` tool (PLAN-REVIEW follow-up #2).

## 8. Follow-up issues to file (after merge)

- [ ] 8.1 **Bash path-extraction hardening**: `--flag=PATH` split, quoted-path
      handling. Threat-model note: does *not* pursue a full shell parser
      (matches the extension's stated guardrail model). Make the README's
      "preventing" claim defensible.
- [ ] 8.2 **Optional `sandbox_radius` query tool**: for agents that want to
      re-fetch the radius after a mid-turn autosave, eliminating the snapshot
      lag at the cost of one tool call. Supplement to the per-turn block.

---

## Mapping: decision → task

| Decision | Task |
|---|---|
| Q1 framing (disclosure, not enforcement) | §7 out-of-scope |
| Q3 `before_agent_start` channel | 3.1 |
| Q4 paths-only | 2.4, 2.5 (no commands/tools in block) |
| Q5 raw globs + gloss | 2.3 (gloss in header), 2.4–2.5 (verbatim) |
| Q6 mode-aware negated block | 2.2 |
| Q7 single channel (drop b) | §7 |
| Q8 autoAllow footnote | 2.6 |
| Q9 cwd anchor resolution | 2.4 |
| Q10 unbypassable header + flat denies | 2.3, 2.5 |
| Q11 snapshot, no note | 3.5 (accept lag), 5.2 (document) |
| Q12 extraction deferred | §7, 5.3, 8.1 |
| Q13 zero-config | §7, 5.5 |
| Q14 compact + capped denies | 2.5 |
| Q15 `disclosure.ts` module | 2.1 |