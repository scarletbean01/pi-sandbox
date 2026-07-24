# sandbox

Configurable guardrails for [pi](https://github.com/earendil-works/pi-mono): an
extension that controls **which bash commands** the agent may run, **which
folders** it may read/write/scan, and **which tools** it may call — using an
allowlist + denylist + ask policy model.

**Threat model: guardrails, not a security boundary.** The sandbox protects
against an LLM *accidentally* doing something dangerous (`rm -rf` in the wrong
directory, writing to `.env`, pushing to origin). A determined adversary could
bypass pattern matching; that is accepted. If you need a real boundary, use OS
level isolation instead.

## How it works

Every tool call the agent makes is evaluated in this order:

1. **Mode check** — `mode: "off"` or the `--no-sandbox` flag allows everything.
2. **Tools policy** — the tool name is matched against `tools.deny` →
   `tools.allow`. For custom tools (registered by other extensions, e.g.
   context-mode's `ctx_execute`) this is the *only* check; unlisted custom
   tools fall back to `tools.default` (`"allow"` unless configured). For the
   built-in tools below, evaluation continues.
3. **Command policy** (`bash` only) — the command string is split on
   `&&`, `||`, `;`, `|` and **every segment** is matched against
   `commands.deny` → `commands.allow`. Proxy binaries listed in
   `commands.proxies` (default: `rtk`) are unwrapped first and every unwrapped
   form is checked.
4. **Path policy** — paths from `read`/`write`/`edit`/`grep`/`find`/`ls`
   arguments and path-like tokens inside bash commands (including `cd`
   targets) are matched against `paths.deny` → `paths.allow`.

Verdicts: **deny** → blocked with a reason shown to the agent; **allow** →
runs; **unlisted** → you are prompted (see Ask UX). In non-interactive modes
(`pi -p`, RPC without UI) unlisted means **blocked** (fail-closed). Handler
errors also fail closed. Your own `!` / `!!` shell commands (`user_bash`) are
never gated.

## Installation

The extension lives at `~/.pi/agent/extensions/sandbox/` and is auto-discovered
by pi (hot-reloadable via `/reload`). Dependencies are installed in that
directory (`picomatch`, pinned). To copy it elsewhere, preserve the whole
directory including `package.json` and `node_modules`.

## Configuration

Two JSONC files (comments allowed), both optional:

| File | Scope | When used |
|---|---|---|
| `~/.pi/agent/sandbox.json` | Global base | Always |
| `<project>/.pi/sandbox.json` | Project overlay | Only when the project is trusted |

Lists merge (defaults < global < project, concatenated); scalar keys
(`mode`, `tools.default`, `commands.proxies`) override: project wins over
global wins over built-in default. **Denies always win** at evaluation time —
a project can never remove a global or built-in deny.

Auto-saves (from "Always allow …" choices and `/sandbox on|off`) write to the
project file when trusted, else the global file. They preserve existing keys
but **drop comments**.

### Matching rules

**Command globs** (commands, tools): `*` matches *any* text, including
slashes — segments are not paths. All other characters are literal. A trailing
` *` also matches the bare command: `git push *` denies bare `git push` too.
Examples: `git status` (exact), `npm *` (any npm invocation), `ctx_*` (tool
name prefix).

**Path globs** (paths): `*` stays within one path segment, `**` matches any
depth. `~` expands to `$HOME`. Relative patterns resolve against the session
cwd (`./**` = the project subtree, `./.gradle/**` = anchored to the repo).
Patterns starting with `**/` match *anywhere* (`**/.env` in any directory).
Existing paths are canonicalized with `realpath` (symlink aliases resolved).

**Proxy unwrapping**: if a segment's binary is in `commands.proxies`, it is
stripped (up to 3 levels) and deny is checked on *all* forms (any match
blocks), then allow on all forms (any match passes). So `rtk git push` is
caught by `git push *`, `rtk git status` passes via `git status`, and
`rtk *` in the deny list is a kill switch for the proxy itself. The ask dialog
shows the inner command (with a `via rtk` marker) and persists inner patterns.
Native proxy subcommands (e.g. `rtk gain`) can be allowlisted as full-segment
patterns. Proxy flags and env prefixes are not parsed — they degrade to ask.

### Built-in policy (always active)

- `paths.allow`: `["./**"]`
- `paths.deny`: `["**/.env", "**/.env.*", "**/.git/**", "**/.ssh/**", "**/id_rsa*", "**/*.pem"]`
- `commands.allow`: `[]`
- `commands.proxies`: `["rtk"]`
- `commands.deny` (hard, **non-overridable**): `eval *`, `bash -c *`, `sh -c *`,
  `sudo *`, `rm -rf /`, `rm -rf ~*`, `mkfs*`, `dd *of=/dev/*`
- `tools`: `{ allow: [], deny: [], default: "allow" }`
- `mode`: `"enforce"`

### Full config reference

Every available key, with comments — also at
[`examples/full-reference.sandbox.jsonc`](examples/full-reference.sandbox.jsonc):

```jsonc
{
  // "enforce": apply policy. "off": allow everything.
  // Toggle: /sandbox on|off (persists here). Bypass once: pi --no-sandbox.
  "mode": "enforce",

  "tools": {
    // Tool-name allowlist (command-glob syntax). Custom tools listed here
    // run without prompting. Built-ins listed here STILL get command/path
    // checks — this is a name gate, not an exemption.
    "allow": ["ctx_search"],
    // Tool-name denylist, checked first. Blocks extension-registered tools
    // that execute LLM-written code, or disables a built-in entirely.
    "deny": ["ctx_execute", "mcp_*"],
    // Verdict for CUSTOM tools in neither list: "allow" (default) or "ask".
    // Built-ins are unaffected (they always use command/path policy).
    "default": "allow"
  },

  "commands": {
    // Bash command allowlist. Every segment of a &&/||/;/| chain must pass.
    "allow": ["./gradlew *", "git status", "git diff *", "npm *"],
    // Bash command denylist, checked before allow. Carve exceptions out of
    // broad allows (allow "git *", deny "git push *").
    "deny": ["git push *", "rm -rf *"],
    // Proxy binaries unwrapped before matching (OVERRIDE semantics:
    // replaces the default, does not append). [] disables unwrapping.
    "proxies": ["rtk"]
  },

  "paths": {
    // Path allowlist. Applies to read/write/edit/grep/find/ls AND to
    // path-like tokens inside bash commands (including cd targets).
    // Default when empty: ["./**"] (project subtree).
    "allow": ["./**", "~/Projects/**"],
    // Path denylist, checked first. Built-in defaults (always active):
    // **/.env, **/.env.*, **/.git/**, **/.ssh/**, **/id_rsa*, **/*.pem
    "deny": ["**/*.jks", "**/secrets/**"]
  }
}
```

A real-world project config for a Gradle + Spring Boot microservice:
[`examples/gradle-spring-boot.sandbox.jsonc`](examples/gradle-spring-boot.sandbox.jsonc).

## Ask UX

Unlisted items open a select dialog:

- **Command**: `Allow once` / `Always allow "<exact>"` / `Always allow "<binary> *"` / `Deny`
- **Path**: `Allow once` / `Always allow this path` / `Always allow "<path>/**"` / `Deny`
- **Tool**: `Allow once` / `Always allow "<tool>"` / `Deny` (exact names only)

`Allow once` caches the exact string (full command / normalized path / tool
name) for the rest of the session. `Always …` writes to the project config
when trusted, else the global one, and notifies where it landed.

## Commands and flags

| Surface | Effect |
|---|---|
| `/sandbox on` / `/sandbox off` | Set mode, persist to config, update footer |
| `/sandbox status` | Mode, config files, per-section counts |
| `/sandbox list` | Dump the effective policy to the chat |
| `pi --no-sandbox` | Disable for this invocation only (never persisted) |
| `/reload` | Re-reads config files (extension reload) |

The footer shows `sandbox: enforce` / `sandbox: off` so a permissive state is
never silent.

## Notes for AI agents

If you are an AI agent running *inside* a sandboxed pi session:

- A block reason like `Command segment "X" matches deny pattern "Y"` or
  `Path "P" matches deny pattern "Y"` is **final** — do not retry the same
  operation with cosmetic variations (quoting, variable indirection, `cd`
  chains). Ask the user to adjust the policy instead.
- If an operation you need is unlisted, the user gets a prompt; state clearly
  *why* you need it so they can make an informed choice.
- `ctx_execute`-style tools and interpreters (`python3 -c`, `node -e`) may be
  denied even when bash works — that is deliberate, not a malfunction.
- When editing `sandbox.json` by hand: JSONC comments are fine; keep deny
  entries for anything destructive; prefer narrow allows (`git status`) over
  broad ones (`git *`); test with `/sandbox list` after `/reload`.

## Development

- Source: `index.ts` (wiring), `policy.ts` (engine), `commands.ts` (command
  matching, proxy unwrapping), `paths.ts` (path matching), `config.ts`
  (loading/merging/persistence, JSONC), `ask.ts` (dialogs)
- Typecheck: `npx tsc --noEmit` in the extension directory (strict,
  `erasableSyntaxOnly`)
- Design history and test matrix: [`PLAN.md`](PLAN.md)
