# PLAN — sandbox.ts extension

A configurable pi extension that gates which bash commands the agent may run and which
folders it may read/write/scan, using an allowlist + denylist + ask policy model.

Threat model: **guardrails**, not a security boundary. Protects against an LLM
accidentally doing something dangerous. A determined adversary could bypass pattern
matching; that is accepted.

## Design summary (agreed decisions)

- **Policy model:** allowlist + denylist + ask. Deny → block; allow → run; unlisted →
  prompt the user (fail-closed in non-interactive modes). Global mode
  `"enforce" | "off"`; `off` allows everything.
- **Config:** layered JSON. Global `~/.pi/agent/sandbox.json` as base, project
  `.pi/sandbox.json` merged on top (only when `ctx.isProjectTrusted()`). Project
  entries add allows/denies; denies win. Both files optional.
- **Commands:** split bash command strings on `&&`, `||`, `;`, `|`; every segment is
  matched against the policy. Deny first, then allow, else ask. Path-like tokens
  and `cd` targets inside bash commands are additionally checked against the path
  policy (strict `cd` gating). Command globs use a regex translation (`*` matches
  any text incl. slashes — commands are not paths); a trailing ` *` also matches
  the bare command (`git push *` denies bare `git push`).
- **Proxy unwrapping (rtk):** segments whose binary is in `commands.proxies`
  (default `["rtk"]`) are unwrapped recursively (max 3). Deny is checked on the
  full segment AND every unwrapped form (either wins); then allow on all forms
  (either wins); else ask. `rtk *` in deny = kill switch. Ask dialog shows the
  inner command with a `(via rtk)` marker and persists inner patterns; "allow
  once" caches the full original segment. rtk's own flags and env prefixes are
  not parsed — they degrade to ask (fail-safe).
- **Tools policy:** `tools: { allow, deny, default? }` matched (command-glob) on
  the tool name, evaluated for EVERY tool call right after the mode check. For
  the 7 built-ins, command/path checks still run afterwards; for custom tools
  (extension-registered, e.g. context-mode's `ctx_execute`) it is the only
  check. Unlisted custom tools default to allow; optional
  `tools.default: "allow" | "ask"` flips that. Name-denying a built-in
  (`"deny": ["bash"]`) disables it.
- **Paths:** single policy for all file access. Applies to `read`, `write`, `edit`,
  `grep`, `find`, `ls` tool calls and to extracted bash path tokens.
- **Enforcement scope:** agent tool calls only. `user_bash` (`!`/`!!`) exempt.
  Custom tools gated only via the tools policy (name level). Handler errors fail
  closed (rethrow → pi blocks).
- **Ask UX:** granular choices (see Task 9), "always" persists to project config if
  trusted else global, "allow once" cached per exact string for the session.
- **Mode switching:** `/sandbox on|off` persists to config; `--no-sandbox` CLI flag
  overrides per invocation without writing; footer status shows current mode.
- **Config format:** JSONC — `//` and `/* */` comments tolerated by a string-aware
  stripper (comment markers inside string literals survive). Auto-saves preserve
  keys but drop comments.

## Default policy (built-in, overridable except hard denies)

- `paths.allow`: `["./**"]`
- `paths.deny`: `["**/.env", "**/.env.*", "**/.git/**", "**/.ssh/**", "**/id_rsa*", "**/*.pem"]`
- `commands.allow`: `[]` (trained organically via the ask flow)
- `commands.deny` (hard, non-overridable):
  `["eval *", "bash -c *", "sh -c *", "sudo *", "rm -rf /", "rm -rf ~*", "mkfs*", "dd *of=/dev/*"]`
- `mode`: `"enforce"`

## Config file shape

```jsonc
{
  "mode": "enforce",
  "tools": { "allow": [], "deny": ["ctx_execute"], "default": "allow" },
  "commands": {
    "allow": ["npm *", "git status"],
    "deny": [],
    "proxies": ["rtk"]
  },
  "paths": { "allow": ["./**", "~/other-repo/**"], "deny": ["**/.env"] }
}
```

## Tasks

**Status: all tasks implemented and verified (unit assertions + live tmux runs,
including real bwrap execution). Layers: tools policy, command policy with rtk
proxy unwrapping, path policy, JSONC layered config, and the bwrap kernel
boundary with auto-allow (15–18). Example project config:
`examples/gradle-spring-boot.sandbox.jsonc`.**

### 1. Scaffold extension directory

- Location: `~/.pi/agent/extensions/sandbox/`
- `package.json` with pinned `picomatch` dependency and
  `"pi": { "extensions": ["./index.ts"] }`
- `index.ts` entry point exporting the default factory
- Run `npm install --ignore-scripts` in the extension dir

### 2. Types and config loading (`config.ts`)

- `SandboxConfig` type: `{ mode, commands: {allow, deny}, paths: {allow, deny} }`
- `loadConfig(cwd)`: read global + project JSON, tolerate missing/malformed files
  (malformed → notify error, treat as empty; never crash the factory)
- `mergeConfigs(global, project)`: concat allow/deny lists; project `mode` wins if set
- Apply built-in defaults underneath user config; hard denies always appended and
  non-overridable
- Gate project config on `ctx.isProjectTrusted()`
- Cache in memory at `session_start`; write-through on saves; `/reload` re-reads
  via the extension reload lifecycle

### 3. Command matcher (`commands.ts`)

- `splitSegments(command)`: split on `&&`, `||`, `;`, `|`, trim, drop empties
  (best-effort string split, no shell parser)
- `commandGlobToRegex(pattern)`: escape regex metachars, `*` → `.*` (slashes
  included — segments are not paths); a trailing ` *` compiles to `( .*)?$` so
  prefix patterns also match the bare command
- `matchCommandValue(segment, allow, deny)`: deny first, then allow, else ask
- `checkCommand(command, policy)`: evaluate all segments; first deny or ask
  short-circuits; returns `{ verdict, segment }`

### 4. Path matcher (`paths.ts`)

- `normalizePath(p, cwd)`: expand `~`, resolve relative against `ctx.cwd`, collapse
  `.`/`..`, `realpath()` for existing paths (fall back to resolved absolute path for
  non-existent ones)
- `matchPath(p, policy, cwd)`: normalize both pattern and actual path, picomatch
  `**`-glob, deny first then allow else `"ask"`
- `extractPathTokens(segment)`: heuristic — tokens starting with `/`, `~`, `.`, or
  containing `/`; always include `cd` targets
- `checkBashPaths(segment, policy, cwd)`: run `matchPath` on extracted tokens

### 5. Policy engine (`policy.ts`)

- `evaluate(toolName, input, config, cwd)` →
  `{ verdict: "allow" | "deny" | "ask", reason, matchedPattern?, path? }`
- File tools (`read/write/edit/grep/find/ls`): path check on `input.path`
- `bash`: command check per segment + path check per extracted token
- `mode === "off"` or `--no-sandbox` flag → always allow
- Session-scoped "allow once" cache (Set of exact strings) consulted before `ask`

### 6. `tool_call` hook (`index.ts`)

- `pi.on("tool_call", ...)` for the seven gated tools; everything else returns
  `undefined` immediately
- `deny` → `{ block: true, reason }` (+ `ctx.ui.notify` warning when `ctx.hasUI`)
- `ask` → fail closed if `!ctx.hasUI`; otherwise run the ask dialog (Task 9)
- Do not swallow errors; let them propagate so pi fails closed

### 7. Ask dialogs (`ask.ts`)

- Command prompt via `ctx.ui.select`:
  `Allow once` / `Always allow "<exact segment>"` / `Always allow "<binary> *"` / `Deny`
- Path prompt: `Allow once` / `Always allow this path` / `Always allow "<path>/**"` / `Deny`
- `Allow once` → add exact string to session cache, proceed
- `Always …` → persist (Task 8), update in-memory config, proceed
- `Deny`/Escape → `{ block: true, reason: "Blocked by user" }`

### 8. Persistence (`persist.ts`)

- `saveDecision(kind, pattern, cwd)`: append to `.pi/sandbox.json` if project trusted,
  else `~/.pi/agent/sandbox.json`; create file with skeleton if missing; preserve
  existing keys; 2-space JSON
- `ctx.ui.notify("Saved to <path>", "info")` after write

### 9. `/sandbox` command + `--no-sandbox` flag + status

- `pi.registerCommand("sandbox", ...)` with subcommands:
  - `on` / `off` — set mode, persist to config, update status
  - `status` — notify: mode, config file locations, allow/deny counts
  - `list` — `pi.sendMessage` (display-only) dumping the effective policy
  - `getArgumentCompletions` for the subcommands
- `pi.registerFlag("no-sandbox", { type: "boolean", default: false })` — per-invocation
  override, never persisted
- `ctx.ui.setStatus("sandbox", "sandbox: enforce|off")` on `session_start` and on mode
  changes; visible so "off" is never silent

### 10. Non-interactive behavior

- `ctx.hasUI === false` → `ask` verdicts block with reason
  `"Not in allowlist (no UI for confirmation)"`
- Works identically in RPC mode for dialogs (`ctx.hasUI` true)

### 11. Testing

- Test with `pi -e ~/.pi/agent/extensions/sandbox/index.ts` during development, then
  move to the auto-discovered location for `/reload` support
- Manual matrix: allowed command runs; denied command blocked; unknown command prompts
  and each ask choice behaves; `cd /etc && ls` blocked by path policy; `.env` read
  blocked despite `./**` allow; write outside cwd blocked; `/sandbox off` allows all;
  `--no-sandbox` bypasses; `pi -p` blocks unknown without prompting; `!` commands
  exempt; `/reload` picks up hand-edited config

### 12. Tools policy (`config.ts`, `policy.ts`, `ask.ts`, `index.ts`)

- Config: new `tools: { allow: string[], deny: string[], default?: "allow" | "ask" }`
  section; merge like other lists across global/project; `default` from project
  wins over global; absent = `"allow"`
- `evaluate()`: after the mode check, match `toolName` against `tools.deny` →
  `tools.allow` → fall back to `tools.default` (custom tools) / continue
  (built-ins). Command-glob matching (reuse `commandGlobToRegex`). Deny reason:
  `Tool "<name>" matches deny pattern "<pattern>"`
- Built-ins listed in `tools.allow` still run command/path checks afterwards;
  for custom tools the tools verdict is final
- Ask dialog (`askTool`): `Allow once` (cached per tool name for the session) /
  `Always allow "<tool>"` (exact name only, no prefix option) / `Deny`.
  Persistence reuses `saveToConfig` with a `"tool"` kind
- `/sandbox status` and `/sandbox list` include the tools section
- `index.ts`: drop the early `GATED_TOOLS` return — every tool call now goes
  through `evaluate()` (the tools policy must see custom tools)

### 13. Proxy unwrapping (`commands.ts`, `policy.ts`, `ask.ts`, `index.ts`)

- Config: `commands.proxies: string[]`, default `["rtk"]`; merged lists concat
  like allow/deny; `[]` in the effective config disables unwrapping
- `unwrapProxies(segment, proxies)`: returns `[full, ...inner forms]` by
  repeatedly stripping leading proxy binaries (max 3 iterations). No flag or
  env-prefix parsing
- Command check: deny matched against ALL forms (any match → deny), then allow
  against ALL forms (any match → allow), else ask. Applies per segment inside
  `checkCommand`
- Ask dialog: shows the innermost form with a `(via <proxy>)` suffix; choices
  persist INNER patterns (`npm test`, `npm *`); "allow once" caches the full
  original segment. Native proxy subcommands (`rtk gain`) are allowlisted by
  hand as full-segment patterns

### 14. Test updates

- Unit: tools policy (deny custom tool, deny built-in, default ask flips,
  allow passes through to path checks); proxy unwrap (inner deny hits, full-form
  allow hits, kill switch `rtk *`, chains, `rtk --flag x` → ask, once-cache keys)
- Live: install-like simulation — register a dummy `ctx_execute`-style tool from
  a scratch extension, verify deny blocks it and default-ask prompts; simulate
  `rtk git push` (wrapped deny) and `rtk git status` (wrapped allow) via bash
  tool calls in tmux; `/reload` picks up edited `tools`/`proxies` keys

### 15. bwrap config section (`config.ts`)

- `BwrapConfig`: `{ enabled, autoAllow, network: "allow" | "off", allowWrite[],
  denyRead[], maskEnv[], fallback: "ask" | "block", userBash }`
- Defaults: `enabled: true`, `autoAllow: false`, `network: "allow"`,
  `allowWrite: ["~/.gradle", "~/.m2", "~/.npm", "~/.cache"]`,
  `denyRead: ["~/.ssh", "~/.aws", "~/.gnupg", "~/.kube", "~/.docker/config.json"]`,
  `maskEnv: ["AWS_*", "GITHUB_TOKEN", "*_API_KEY", "*_SECRET*"]`,
  `fallback: "ask"`, `userBash: false`
- Parse + merge like other sections (lists concat, scalars override)

### 16. bwrap wrapper (`bwrap.ts`)

- `probeBwrap()`: cached per session — `bwrap --version` + trivial launch
  (`--unshare-user --ro-bind / / -- true`); `/reload` re-probes
- `buildBwrapCommand(original, cfg, cwd, env)`: namespaces
  (`--unshare-user/pid/ipc/uts --die-with-parent --new-session`),
  `--ro-bind / / --dev /dev --proc /proc`, writable binds for cwd + `$TMPDIR` +
  existing allowWrite dirs, `--tmpfs` over existing denyRead dirs,
  `--ro-bind /dev/null` over denyRead files (missing paths skipped),
  `--unsetenv` for env keys matching maskEnv globs, `--unshare-net` when
  network off, `--chdir cwd`, `-- sh -c '<single-quote-escaped original>'`
- Bash tool override via `createBashTool(cwd, { spawnHook })` registered on
  `session_start` when enabled; spawnHook rewrites the command. Guardrail's
  `tool_call` still sees the original (pre-wrap) command — layering preserved
- Fallback: bwrap unavailable → `"ask"`: run unwrapped + one-time degraded
  warning + footer marker; `"block"`: spawnHook throws (tool errors, fail-closed)
- `user_bash`: when `bwrap.userBash: true`, supply custom `operations.exec`
  that runs the bwrap-wrapped command; default exempt

### 17. Auto-allow integration (`policy.ts`, `index.ts`)

- `PolicyState.bwrap: { active: boolean, autoAllow: boolean }`
- In `evaluate()`: bash-derived `ask` verdicts (command AND path-token kinds)
  downgrade to allow when `active && autoAllow`; denies never downgrade;
  file-tool asks never downgrade
- Footer: `sandbox: enforce+bwrap` normally, degraded marker when bash runs
  unsandboxed; `/sandbox status` and `/sandbox list` include the bwrap section

### 18. bwrap tests

- Unit: arg building (binds, tmpfs/null denies, unsetenv globs, unshare-net,
  escaping, missing-path skips), config parse/merge, autoAllow verdict matrix
- Live (tmux): write outside cwd fails inside sandbox (`touch /etc/x` /
  `touch ~/<file>`), cwd write works, `cat ~/.ssh/id_rsa` fails (tmpfs deny),
  masked env var empty, autoAllow flips a would-be-ask command to silent run,
  fallback=ask path with bwrap "missing" (PATH manipulation) prompts with
  degraded warning
