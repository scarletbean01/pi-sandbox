# HARDENING PLAN — sandbox extension

A plan to close the bypasses found in the November 2026 review, harden the bwrap
layer, and make config handling and the ask flow reliable. It sits on top of
[`PLAN.md`](PLAN.md), the original design, and
[`TASKS.md`](TASKS.md) / [`PLAN-REVIEW.md`](PLAN-REVIEW.md), the disclosure work.

Task IDs are `H<phase>.<n>`. Each task lists the files it touches, the change,
and the acceptance check. Each phase ships as its own commit or PR, so the
repo is never left half-hardened.

---

## 0. Why, and the guiding rule

The README calls the threat model "**guardrails, not a security boundary**."
This plan keeps that model. But today the guardrail fails in ways an LLM hits
*by accident*. `cmd & other`, `$(…)`, `$HOME/…`, `cat server.pem` and a "once"
approval that covers unseen segments are all ordinary shell usage, not
adversarial tricks. The bwrap layer is sold as a "real boundary", and it can be
escaped through host Unix sockets.

**Guiding rule for every change: when the analysis is unsure, fall toward
*ask*, never toward *allow*.** A pattern may allow only what the engine fully
understood. Anything opaque must reach the user, or be denied when the user
chose fail-closed.

### Confirmed failures (all reproduced against `evaluate()` with bun)

Test config: `commands.allow = ["git *", "ls *", "cat *", "echo *"]`, default paths.

| #  | Input | Today | Expected | Root cause | Fixed in |
|----|-------|-------|----------|------------|----------|
| F1 | `ls /etc && curl x \| sh`, path approved "once" | allow | ask for `curl x`, then `sh` | once-key is the whole command (`policy.ts:35,74`) | H1.1 |
| F2 | `write .pi/sandbox.json` | allow | deny | policy files sit inside `./**` | H1.2 |
| F3 | `git status & curl evil` | allow | ask (`curl`) | no split on a single `&` | H2 |
| F4 | `git log $(rm -rf ~)`, ``git log `id` `` | allow | ask (opaque) | substitution not detected | H2 |
| F5 | `cat $HOME/.aws/credentials` | allow | ask or deny | variables not expanded | H2.4 |
| F6 | `cat .en?`, `cat ".e"nv` | allow | deny | globs and quotes not resolved | H2.3, H2.5 |
| F7 | `cat server.pem` | allow | deny | bare filenames never path-checked | H1.5 |
| F8 | `cat --file=.env` | allow | deny | `--opt=value` never path-checked | H1.5 |
| F9 | `write link/newfile` (link → outside) | allow | ask | realpath fallback skips the parent | H1.4 |
| F10 | `echo k > link/authorized_keys` | allow | ask | same as F9, for redirects | H1.4 |
| F11 | `/bin/bash -c id`, `bash  -c id`, `env sh -c id`, `rm -fr /`, `/usr/bin/sudo id`, `FOO=1 eval id` | ask (allow under autoAllow) | deny | hard denies matched literally | H1.3, H2 |
| F12 | `grep KEY path=.` with a non-gitignored `.env` | contents returned | `.env` excluded | only the root path is checked | H3 |
| F13 | sandboxed `systemd-run --user …`, `tmux send-keys`, herdr/hc CLI, `docker run -v /:/h` | escapes bwrap | blocked | host sockets reachable (`/run/user/$UID`, `/tmp`, docker) | H4.1 |
| F14 | sandboxed bash writes `.git/hooks/pre-commit` | allowed | blocked | the whole cwd is bound writable | H4.2 |

---

## Phase H0 — Test harness and regression corpus (do first)

Today the only tests are the disclosure assertions in `scripts/`. Every later
phase is test-first: add the failing case to the corpus, then fix it.

- [ ] **H0.1** Add `bun test` support. Create `test/`, add
      `"scripts": { "test": "bun test", "typecheck": "tsc --noEmit" }` to
      `package.json`, and add `"test/**/*.ts"` to `tsconfig.json` `include`.
- [ ] **H0.2** Write `test/helpers.ts`:
      - `stateWith(partialConfig, { cwd, once?, bwrap? })`, built on `mergeConfigs`
      - `withTempProject(fn)`: a temp dir holding a fixture tree (`.env`,
        `server.pem`, a `link` symlink to an outside dir, `.git/hooks/`,
        `.pi/sandbox.json`), removed afterwards
- [ ] **H0.3** Write `test/bypass-corpus.test.ts`: a table of `{ input, tool,
      expected verdict, expected kind/subject }`, seeded with F1–F12. Mark a
      case `test.todo` until its phase lands, then flip it to a real
      assertion. The corpus is the contract: it only grows.
- [ ] **H0.4** Add unit tests for today's behavior that must survive:
      `commandGlobToRegex` (the bare-suffix rule), proxy unwrapping (deny on any
      form, allow on any form), `stripJsonComments` (`"dd *of=/dev/*"`
      survives), `mergeConfigs` layering, and the disclosure renderer
      (move `scripts/verify-disclosure.ts` into `test/disclosure.test.ts`).
- [ ] **H0.5** Add a CI or pre-commit gate: `npm run typecheck && bun test`.
      Use a GitHub Action if a remote is added, otherwise a
      `.githooks/pre-commit` plus a README note.

**Acceptance:** `bun test` is green, with F1–F12 listed as todo.

---

## Phase H1 — Critical fixes that need no parser

Small, local changes that close the worst holes before the bigger H2 rewrite.

### H1.1 Scope "Allow once" to what the user actually saw (F1)

- `policy.ts`: drop `cmd:${command}` as the cache key for a partial
  approval. Each ask returns a key for its own subject:
  - command asks: `seg:<canonical form>`
  - path asks: `path:<normalized path>` (as file tools already do)
- `evaluateBash` checks the cache per segment form and per path token, so
  approving `/etc` no longer approves `curl x | sh`.
- Split the meaning of "once":
  - **"Allow once"**: covers only this tool call. Keep the approvals in a
    per-call `Set` created in the `tool_call` handler's loop and passed in as
    `state.callApprovals`. Throw it away when the call finishes.
  - **"Allow for this session"** (new choice): goes into today's session-wide
    `onceCache`.
- `ask.ts`: add the session option to all three dialogs.
- Keep the whole-command key only for an explicit choice in the command
  dialog: **"Allow this exact command once"**.

**Acceptance:**
- F1 asks for `curl x`, then `sh`, each separately.
- An approval in call A does not carry over to an identical call B unless
  "session" was chosen.

### H1.2 Self-protection: the agent cannot edit its own policy (F2)

- `paths.ts` / `policy.ts`: introduce an **access mode**:
  - `read`, `grep`, `find`, `ls` → `"read"`
  - `write`, `edit`, and bash redirect targets → `"write"`
  - all other bash path tokens → `"unknown"`, treated as write for this check
- `config.ts`: add `PROTECTED_WRITE_PATHS`, computed at load time:
  - `globalConfigPath()` and `projectConfigPath(cwd)`, plus `*.bak` and `*.tmp` siblings
  - the extension's own directory (`import.meta.dirname`), unless the global
    config sets `selfEdit: true` (needed when the cwd *is* the extension, as
    in this repo)
  - `<cwd>/.git/hooks/**` and `<cwd>/.git/config` (also enforced by the kernel in H4.2)
- These are **hard denies for write access**, applied before user lists and
  not overridable by project config. Reads stay allowed: the agent may read
  its policy, and disclosure already shows it.
- Block reason: `Path "…" is sandbox policy; edit it yourself or use /sandbox`.

**Acceptance:**
- F2 is denied.
- `read .pi/sandbox.json` is allowed.
- `echo x > .pi/sandbox.json` is denied.
- `/sandbox` subcommands still write (they don't go through `tool_call`).

### H1.3 Canonicalize segments before deny matching (F11, interim)

A stopgap that works on a whitespace split until the H2 parser lands. H2
keeps these rules but applies them to `argv` arrays from the AST.

- `commands.ts`: add `canonicalize(segment)`:
  1. Collapse runs of whitespace.
  2. Strip leading `NAME=value` assignments.
  3. Strip wrapper commands, repeatedly: `env` (and its `-i`/`-u X`/`VAR=` args),
     `command`, `builtin`, `exec`, `nice [-n N]`, `nohup`, `timeout <dur>`,
     `stdbuf -…`, `time`, `chrt …`, `ionice …`, `setsid`.
  4. Reduce argv0 to its basename (`/usr/bin/sudo` → `sudo`).
  5. Combine short flags (`-fr`, `-r -f` → `-rf`) **for the `rm` hard-deny check only**.
- **Deny** matching tests every form: raw, canonical, and proxy-unwrapped.
- **Allow** matching stays on the *raw* form with an exact argv0. Matching
  allows on the canonical form would let `/tmp/evil/git status` match
  `git *`. A path-qualified argv0 matches only a pattern that names that path.
- Extend `HARD_COMMAND_DENIES`:
  - `doas *`, `su *`, `pkexec *`, `run0 *`
  - `zsh -c *`, `dash -c *`, `ksh -c *`, `fish -c *`, `busybox sh *`
  - `rm -rf /*`, `rm -rf ~/*`, `chmod -R * /`, `chown -R * /`
  - `* > /dev/sd*`, `* > /dev/nvme*`
- Add a **NEVER_AUTO** class. These always ask, are never downgraded by
  `autoAllow`, and are never persisted as a prefix:
  - `python* -c *`, `node -e *`, `perl -e *`, `ruby -e *`, `bun -e *`, `deno eval *`
  - `xargs *`, `find * -exec*`, `find * -delete*`, `git -c *`

**Acceptance:**
- Every F11 variant is denied.
- `python3 -c 'print(1)'` asks even with `autoAllow: true`.

### H1.4 Path canonicalization through symlinked parents (F9, F10)

- `paths.ts normalizePath`: when `realpath` fails, walk up to the deepest
  ancestor that exists, `realpath` that, and re-append the missing tail.
- Check deny against **both** the lexical path and the real path. A deny on
  either wins: this catches `.git/x` when `.git` is a symlink. Allow requires
  the **real** path to match.

**Acceptance:** F9 and F10 ask, showing the real target outside the project.

### H1.5 Check bare words and `--opt=value` as paths (F7, F8)

- `extractPathTokens`: treat a non-flag argument word as a path candidate when:
  - it looks like a path (today's rule), **or**
  - it exists on disk relative to the effective cwd, **or**
  - its resolved form matches any `paths.deny` pattern (catches new files
    such as `touch server.pem`)
- For `--name=value` and `-o=value`, check the value too.
- Redirect targets (`>`, `>>`, `2>`, `&>`, `<`) are always paths, with
  access `write` (or `read` for `<`).

**Acceptance:**
- F7 and F8 are denied.
- `git commit -m fix` causes no extra asks: `fix` doesn't exist and matches no deny.

### H1.6 Fail closed on handler errors

- `index.ts`: wrap the `tool_call` body in `try/catch`. On error, return
  `{ block: true, reason: "sandbox: internal error (…), failing closed" }`
  and notify. This doesn't rely on pi's own handling, which isn't documented
  in `types.d.ts`.

**Acceptance:** a stubbed `evaluate` that throws blocks the call.

---

## Phase H2 — Parse bash with tree-sitter-bash (F3–F6)

**Decision: use `tree-sitter-bash` through `web-tree-sitter` (wasm).**
Spike results from 2026-11-10, with Bun 1.4.4, the same runtime pi
0.81.1 is built on:
- `web-tree-sitter@0.27.1` (MIT, 208 KB wasm) and `tree-sitter-bash@0.25.1`
  (MIT, 1.3 MB wasm) load with no native build.
- `Parser.init()` plus `Language.load()` takes ~23 ms, once per session. A
  parse takes 0.1–1.4 ms per command.
- The parser finds every command, including those inside substitutions:

| Input | `command` nodes found | `hasError` |
|---|---|---|
| `git status & curl evil` | `git status`, `curl evil` | no |
| `git log $(rm -rf ~)` | `git log $(rm -rf ~)`, `rm -rf ~` | no |
| `rg "TODO\|FIXME\|HACK" src` | one command (fixes the polluted allowlist) | no |
| `cat .en? > out 2>&1` | `cat .en?` (redirect is a separate node) | no |
| `echo 'unterminated` | `echo` | **yes** |

So nested commands are **checked as commands** rather than just flagged as
opaque. That's stricter and gives fewer false asks than a hand-written lexer.

- [ ] **H2.0** Spike inside pi itself: a throwaway extension that loads the
      wasm from `node_modules` and parses one command on `session_start`.
      This proves pi's compiled binary resolves `require.resolve(...wasm)`
      and allows `WebAssembly` from an extension. If it fails, fall back to
      bundling the two `.wasm` files next to `index.ts` and loading them by
      `import.meta.dirname` path. If that fails too, stop and fall back to a
      hand-written, dependency-free lexer. It would split on separators,
      understand quoting and redirects, and mark `$(…)`, backticks,
      heredocs, subshells and control flow as opaque. Same `Analysis`
      interface, less precise: nested commands become *ask* instead of being
      checked.
- [ ] **H2.1** Dependencies: add the exact pins `"web-tree-sitter": "0.27.1"`
      and `"tree-sitter-bash": "0.25.1"` to `dependencies`, and install with
      `--ignore-scripts`: only the shipped `.wasm` is needed, no
      node-gyp. Add a test that asserts both wasm files load, so a version bump
      that breaks ABI compatibility fails CI.
- [ ] **H2.2** `shell.ts`:
  - `initShell(): Promise<void>` loads once, from `session_start`. The
    `tool_call` handler is async, so it awaits `initShell()` if parsing is
    requested before init finishes.
  - `analyze(command): Analysis` walks the AST and returns:
    - `Analysis = { commands: Cmd[], paths: PathRef[], opaque: OpaqueReason[], parseError: boolean }`
    - `Cmd = { argv: Word[], text: string, nested: boolean /* inside $(), ``, <(), subshell, function */, cwd: CwdState }`
    - `Word = { value: string /* quotes removed, escapes resolved */, literal: boolean, expansions: string[], glob: boolean }`
    - `PathRef = { word: Word, access: "read" | "write" | "unknown", source: "arg" | "redirect" | "cd" }`
  - Node handling:
    - Each `command` node becomes a `Cmd`, whether found at the top level, in
      `pipeline`, `list`, `subshell`, `command_substitution`,
      `process_substitution`, `function_definition`, or in the bodies of
      `if`/`for`/`while`/`case`.
    - `file_redirect` becomes a `PathRef` (`>`/`>>`/`&>` → write, `<` → read).
    - `heredoc_redirect`/`herestring` → the input is data. Note it, but it isn't a path.
    - `variable_assignment` prefixes are stripped from argv (they feed H1.3
      canonicalization).
    - `concatenation`, `string`, `raw_string` and `ansi_c_string` are
      resolved to a literal `value` when every part is literal. Otherwise
      `literal: false`, with the reason recorded.
  - **Opaque** (cannot be allow-matched, at least *ask*):
    - `rootNode.hasError` or any `MISSING` node
    - argv0 that isn't literal (`$CMD args`, `$(which x) …`)
    - `eval`-like reuse of data: `source`/`.` with a non-literal file
    - any node type the walker doesn't know (an explicit allowlist of handled
      node types; anything else is opaque, so grammar upgrades fail safe)
- [ ] **H2.3** Policy over the analysis (`policy.ts`, `commands.ts`):
  - **Every** `Cmd`, nested ones included, goes through deny → allow → ask.
    Matching uses a normalized string made by joining the `argv` values with
    single spaces. `git log $(rm -rf ~)` therefore checks `rm -rf ~` against
    the hard denies and is denied.
  - A `Cmd` whose argv contains a non-literal word can match **deny**
    patterns, but **never** an allow. That makes it at least *ask*.
  - Any opaque reason, or a parse error, makes the whole command at least
    *ask*. `autoAllow` may downgrade it only while bwrap is active. The
    dialog shows the reason.
  - Proxy unwrapping (`rtk`) and H1.3 canonicalization work on `argv`
    arrays rather than strings.
- [ ] **H2.4** Globs: a path word with an unquoted `*`, `?` or `[…]` is
      expanded with `fs.globSync` (available in Bun 1.4 and Node ≥ 22),
      relative to the effective cwd. Every match is path-checked, and a deny
      on any match wins. No matches → check the literal. More than 500
      matches → ask. Fixes `.en?`.
- [ ] **H2.5** Variables: statically substitute `$HOME`, `~`, `$PWD`,
      `$TMPDIR`, `$USER` in path words. Any other expansion in a path word →
      *ask* (unknown target). It is never resolved against cwd as a literal
      string. Fixes F5.
- [ ] **H2.6** Quotes: path checks use `word.value`, so `".e"nv` → `.env`.
      Fixes F6.
- [ ] **H2.7** `cd` tracking: walk the commands in execution order. After a
      literal `cd X` in the same list, later relative paths resolve against
      `X`. In a subshell or substitution the cd scope ends with that node.
      After `cd` with a non-literal target, `cd -`, or `pushd`, relative
      paths are unknown → *ask*.
- [ ] **H2.8** Parser unavailable (wasm failed to load): stay usable but
      **fail toward ask**. No bash command can be allow-matched, so every
      bash call asks, unless bwrap is active with `autoAllow`. Denies still
      apply to a whitespace-split fallback. Show `sandbox: parser!` in the
      footer and log the cause. With `bwrap.fallback: "block"`, bash is
      blocked instead.
- [ ] **H2.9** Delete `splitSegments` and the old `extractPathTokens`. Add a
      property test: for generated commands (corpus atoms joined with `;`, `&`,
      `|`, `$(…)`, backticks, `<(…)`, subshells), any atom that is
      hard-denied makes the whole command denied, and any unlisted atom keeps
      it out of *allow*.

**Acceptance:**
- F3–F6 resolve as the table says.
- `git log $(rm -rf ~)` is **denied**, not just asked about.
- `rg "TODO|FIXME|HACK"` is one command.
- Corrupting the wasm path produces the H2.8 behavior, not a crash.

---

## Phase H3 — File tools must not leak denied children (F12)

`grep` runs `rg --hidden` and skips only `.gitignore`d files. `find` and `ls`
list names. Today only the root `path` argument is checked.

- [ ] **H3.1** Use the `tool_result` hook to filter results, the main defense
      because it is hard to bypass. For `grep`, `find` and `ls` results, parse
      each output line's path, `normalizePath` it, and drop lines whose path
      matches `paths.deny`. Append
      `[sandbox: N results hidden by deny policy]` so the agent isn't confused.
- [ ] **H3.2** Rewrite the input as a second layer. In `tool_call`, give
      `grep` an extra exclusion when the search root contains denied matches.
      Prefer overriding the tool with `createGrepTool(cwd, { operations })`,
      the same pattern as bash, so the deny globs reach rg as `--glob '!…'`.
      Mutating `input.glob` doesn't work because it's a single string.
- [ ] **H3.3** `grep`/`find`: also check the optional `glob`/`pattern`
      inputs. A `glob` that matches *only* denied files (e.g. `glob: ".env"`)
      is denied outright with a clear reason.
- [ ] **H3.4** `edit`: confirm the only path input is `path` (verified for
      pi 0.81.1, where `edits[]` holds only `oldText`/`newText`). Add a unit
      test so a future schema change fails loudly. The test asserts the keys
      in `createEditTool(...).parameters`.

**Acceptance:**
- F12 returns matches only from allowed files, plus the hidden-count note.
- `ls .` shows no `.env` line.

---

## Phase H4 — bwrap hardening (F13, F14)

### H4.1 Close host-socket escapes (F13)

- `bwrap.ts`:
  - `--tmpfs /run/user/$UID` (kills the D-Bus user bus, systemd user
    manager, pipewire/pulse, Wayland, gpg-agent and keyring sockets).
  - `--tmpfs /run/dbus` and `--ro-bind /dev/null` over, for each one that
    exists: `/var/run/docker.sock`, `/run/docker.sock`, `/run/podman/`,
    `/run/containerd/`, `/run/snapd.socket`, `/run/libvirt/`.
- **Private `/tmp`**: today the host `/tmp` is bound writable, which exposes
  `/tmp/tmux-$UID`, `/tmp/.X11-unix`, `/tmp/ssh-*` agent sockets and other
  users' scratch files. Change to a per-session
  `fs.mkdtempSync(os.tmpdir()/pi-sbx-)`, bound onto `/tmp` inside the
  sandbox, with `--setenv TMPDIR /tmp`. Delete it on `session_shutdown`
  (check the event exists) or at the next `session_start`.
- Always unset (in addition to `maskEnv`): `SSH_AUTH_SOCK`,
  `DBUS_SESSION_BUS_ADDRESS`, `XDG_RUNTIME_DIR`, `DISPLAY`,
  `WAYLAND_DISPLAY`, `TMUX`, `TMUX_PANE`, `STY`, `ZELLIJ*`,
  `KITTY_LISTEN_ON`, `WEZTERM_*`, `HERDR*`, `HC_*`, `GPG_AGENT_INFO`.
- Opt-out config `bwrap.allowSockets: string[]`, for paths re-bound after the
  tmpfs (e.g. a project that really needs the docker socket). Off by default,
  global-only (see H5.4).
- Document in the README that `network: "allow"` still exposes **abstract**
  Unix sockets (such as `@/tmp/.X11-unix`). Only `network: "off"` isolates them.

### H4.2 Read-only subpaths inside the writable cwd (F14)

- After `--bind cwd cwd`, add `--ro-bind P P` for each of these that exists:
  `.git/hooks`, `.git/config`, `.git/info`, `.pi`, `.envrc`, `.vscode`,
  `.idea`, `.husky`. Expose the list as `bwrap.readOnly` (defaults
  concatenated, same as the other lists).
- Paths that don't exist are skipped. Binding over them would make bwrap
  create stray mount-point files on the host. Document the limit: the agent
  can still *create* `.envrc` if it is missing. H1.2 still blocks the
  guardrail path.

### H4.3 Mirror in-project secret denies into the kernel layer

- `bwrap.maskProjectDenies: true` (default). At `session_start`, glob the
  cwd for `paths.deny` patterns: depth ≤ 6, skip `node_modules` and `.git`,
  stop after 200 hits. Mask each hit (`/dev/null` over files, tmpfs over dirs),
  so `python -c 'open(".env")'` also sees nothing. Re-scan when `/sandbox
  reload` runs. Warn if the cap is hit.

### H4.4 Better default lists

- Add to `denyRead`: `~/.pi/agent/auth.json` (confirm pi's credential file
  name), `~/.config/gh`, `~/.git-credentials`, `~/.netrc`, `~/.npmrc`,
  `~/.pypirc`, `~/.cargo/credentials*`, `~/.config/gcloud`, `~/.azure`,
  `~/.password-store`, `~/.local/share/keyrings`, `~/.mozilla`,
  `~/.config/google-chrome`, `~/.config/chromium`, `~/.config/BraveSoftware`,
  `~/.terraform.d/credentials*`.
- Add to `maskEnv`: `*TOKEN*`, `*PASSWORD*`, `*PASSWD*`, `*_KEY`,
  `*CREDENTIAL*`, `ANTHROPIC_*`, `OPENAI_*`.
- Env handling stays **mask-based** (decision 5). No `--clearenv`
  allowlist mode is planned. Keep the masks reviewable: `/sandbox list`
  shows which of the current env names are masked (names only, never values).
- `allowWrite`: keep the defaults, but document that a writable `~/.cache`
  or `~/.npm` lets a command poison caches used outside the sandbox. Offer a
  narrower example in `examples/`.

### H4.5 Extra namespace and privilege flags

- `--cap-drop ALL`, `--unshare-cgroup-try`.
- `--disable-userns` when the probe shows bwrap ≥ 0.8 supports it (blocks
  nested namespace tricks).
- **Full-form probe:** at session start, run `buildBwrapCommand("true", cfg,
  cwd, env)` rather than the minimal one. A bind or tmpfs that the host
  rejects (AppArmor, odd mounts) then marks bwrap degraded up front, instead
  of failing every bash call later.

### H4.6 Remove stale closures in the bash override

- `index.ts setupBwrap`: `spawnHook` currently keeps the *first* session's
  `cfg` and `ctx.cwd`. Store `currentBwrapCfg` and `currentCwd` in
  module state, update them on every `session_start`, and read them inside
  `spawnHook`.
- When `enabled` is false → pass the command through unwrapped. That removes
  the throw when `fallback: "block"` is stale.

### H4.7 Define how bwrap interacts with "off"

- **Decision (2):** `bwrap.enabled` is independent of
  `mode`. `mode: off` turns off only the pattern guardrail. `--no-sandbox`
  turns off both.
- Fix the disclosure text to match: under `mode: off` with bwrap active, show
  `Guardrail is OFF; bash still runs kernel-sandboxed (bounds: …)` instead
  of "operate freely". Update `disclosure.ts`, its tests and the README.

**Acceptance for H4:** an integration test (`test/bwrap.integration.test.ts`,
skipped when the probe fails) checks that, inside the wrapped shell:
- `test -S /run/user/$UID/bus` is false
- `ls /tmp` is empty at the start of a session
- `touch .git/hooks/x` fails
- `cat .env` (the fixture) is empty
- `echo $SSH_AUTH_SOCK` prints nothing
- a write into `cwd` and into `allowWrite` still succeeds

---

## Phase H5 — Config robustness

### H5.1 A malformed config fails closed, not open

- Today a broken global file is "ignored", which silently drops the user's
  denies.
- New behavior: if either file fails to parse, the effective config becomes
  **strict defaults**: `mode: enforce`, `tools.default: ask`,
  `autoAllow: false`, `bwrap.fallback: block`, plus the built-in denies.
- The footer shows `sandbox: CONFIG ERROR`, and every ask dialog shows a
  banner. `/sandbox status` prints the parse error with line and column.

### H5.2 Validate, don't ignore

- `parseConfigFile` returns `{ config, warnings[] }`. It warns about:
  unknown keys (`"alow"`), wrong types (a string where an array is
  expected), patterns picomatch can't compile, and unknown enum values.
- Show the warnings once per session. Unknown keys still don't break loading.

### H5.3 Safe writes

- `saveToConfig`:
  1. Re-read the file.
  2. **Refuse** to write if the existing file fails to parse (today it is
     overwritten with a skeleton). Tell the user to fix it.
  3. Edit with `jsonc-parser` (`modify` + `applyEdits`, Microsoft's library,
     no dependencies) so comments and formatting survive.
  4. Write to `file.tmp`, `fsync`, `rename`.
  5. Serialize writes inside the process with a promise queue (H6.5).
- Keep one `sandbox.json.bak` of the previous version on every write.

### H5.4 A project config may only tighten the policy

- Trusted projects can still be hostile (cloned repos), and `.pi/` is
  committable. In `mergeConfigs`, **ignore** these project settings and warn:
  - `mode: "off"`
  - `bwrap.enabled: false`
  - `bwrap.autoAllow: true`
  - `bwrap.fallback: "ask"` when the global is `"block"`
  - `bwrap.network: "allow"` when the global is `"off"`
  - `tools.default: "allow"` when the global is `"ask"`
  - `bwrap.allowSockets`, `bwrap.allowWrite` outside the cwd, `selfEdit`
- Project allow lists still add on top (that is what trust means), but
  they're shown with a `(project)` tag in `/sandbox list`.
- Escape hatch: the global config sets `"allowProjectLoosening": true`.
- `/sandbox off` becomes **session-only** by default. `/sandbox off --persist`
  writes `mode` to the **global** file. This also covers this repo's own
  `.pi/sandbox.json`, which has `"mode": "off"` saved.

### H5.5 Default `tools.default` becomes `"ask"` (decision 4)

- `config.ts DEFAULT_CONFIG.tools.default`: change `"allow"` to `"ask"`. Unknown
  custom, MCP and extension tools then prompt once ("once", "session" or
  "always" applies).
- Non-interactive mode (`pi -p`, RPC without UI): unlisted custom tools are
  **blocked** under the new default. Document this, and show it in the block
  reason (`add it to tools.allow in ~/.pi/agent/sandbox.json`).
- First run after upgrading: when the global file doesn't set
  `tools.default`, show a one-time notice listing the custom tools registered
  in this session (`pi.getTools()` or similar; check the API), with the hint
  to allow them.

### H5.6 Reload without restarting

- Add `/sandbox reload`: re-read both files, re-probe bwrap, re-scan the
  H4.3 masks, update the footer.
- Optionally `fs.watch` both files with a 500 ms debounce and reload
  automatically. Ignore the extension's own writes (compare mtimes).

**Acceptance:**
- Corrupting the global file produces strict mode plus a visible error; no
  denies are lost.
- Saving into a commented `.jsonc` keeps the comments.
- Project `mode: off` is ignored with a warning.

---

## Phase H6 — Ask UX

- [ ] **H6.1** The command dialog shows the **full command**, with the
      unknown segment marked (`▶ curl x ◀`) and the opaque reason if there is
      one. Today only the inner form is shown.
- [ ] **H6.2** Safer prefixes:
  - The prefix option becomes **two tokens** when the binary has
    subcommands: `git status *`, not `git *`.
  - For exec-capable binaries (`npx`, `npm`, `pnpm`, `yarn`, `bunx`, `bun`,
    `node`, `python*`, `perl`, `ruby`, `sh`, `make`, `just`, `git`, `find`,
    `sed`, `awk`, `xargs`, `env`, `docker`, `kubectl`, `ssh`, `curl`,
    `wget`), the one-token prefix is either hidden or labeled
    `⚠ runs arbitrary code`.
  - NEVER_AUTO forms (H1.3) get no prefix option at all.
- [ ] **H6.3** The path dialog offers "subtree" only for directories. For a
      file, offer "this file" and "the parent folder `<dir>/**`". Today you
      can get `/dev/null/**` and `…/SKILL.md/**`.
- [ ] **H6.4** Escape glob metacharacters (`* ? [ ] { } ( ) ! +`) in
      persisted literal paths, so a directory named `a[1]` doesn't save a
      broader pattern than intended.
- [ ] **H6.5** Serialize asks. Parallel `tool_call`s each open a dialog
      today, and `saveToConfig` races. Add a single async mutex around
      `resolveAsk` and the save. After acquiring it, **re-evaluate**, because
      an earlier answer may already cover this call.
- [ ] **H6.6** Add `/sandbox test <command or path>`, a dry run that prints
      the verdict, parsed commands (nested ones included), opaque reasons,
      matched patterns and
      whether bwrap would auto-allow it. It is useful for users and is the
      basis for corpus tests.

---

## Phase H7 — Code quality, observability, docs

- [ ] **H7.1** Matcher cache: a `Map<pattern, RegExp | Matcher>` for
      `commandGlobToRegex` and `picomatch`, cleared on reload. Today each
      check recompiles every pattern for every token.
- [ ] **H7.2** Deduplicate helpers. `expandTilde` exists three times
      (`paths.ts`, `bwrap.ts`, `disclosure.ts`). Move it to `util.ts`,
      along with `shq`.
- [ ] **H7.3** Audit log (opt-in, `audit: true` in the global config): one
      JSONL line per decision in `~/.pi/agent/sandbox-audit.jsonl`, holding
      `{ ts, tool, verdict, kind, subject, pattern, via, choice, bwrap }`.
      Never log file contents or env values. Rotate at 5 MB.
- [ ] **H7.4** `ensureLoaded` is lazy and silent today. Log load errors to
      the audit log, and surface them through `/sandbox status`, even when
      there is no UI.
- [ ] **H7.5** README:
  - Rewrite "How it works" around the tree-sitter parse, nested-command
    checks, and opaque → ask. List the two wasm dependencies.
  - Add a "What bwrap does and does not isolate" table (sockets, abstract
    sockets, network, file tools outside bwrap).
  - Document the "project can only tighten" rule, the new dialog choices,
    `/sandbox test` and `/sandbox reload`.
  - Remove the claim that enforcement is "tested" until H0 is in.
- [ ] **H7.6** Update both example configs for the new keys (`readOnly`,
      `allowSockets`, `env`, `maskProjectDenies`, `audit`), with comments
      explaining each.

---

## Ordering and dependencies

```
H0 ──► H1 ──► H2 ──► H6 (dialog depends on parser output)
        H2.0 spike can run in parallel with H1
        │      └───► H3 (path-candidate logic shared)
        └──► H5 (independent; H5.3 shares the mutex with H6.5)
H4 (independent of H1–H3; needs only H0 for its integration test)
H7 last (docs reflect final behavior); H7.1/H7.2 can land anytime
```

Suggested PR sequence:
1. **H0**, tests and corpus.
2. **H1**, the critical fixes.
3. **H4.1, H4.2, H4.6**, the bwrap escapes.
4. **H2**, the tree-sitter parser. Run the H2.0 spike early, alongside PR 2.
5. **H3**.
6. **H5**.
7. **H4.3–H4.5, H4.7**.
8. **H6**.
9. **H7**.

PRs 1–3 close the worst problems quickly (F1, F2, F7–F11, F13, F14) without
waiting on the parser.

## Breaking changes and migration

| Change | Who notices | Migration |
|---|---|---|
| "Allow once" covers one call only; new "session" choice | everyone | the dialog label explains it; old behavior = "Allow for this session" |
| Opaque commands (`$(…)`, heredocs, `&`) no longer match allows | users with broad `git *`-style allows | expect more asks; enable bwrap + `autoAllow` to absorb them |
| Bare filenames and `--opt=path` are path-checked | rare false asks | add a path allow |
| Policy files are write-protected; extension dir needs `selfEdit` | developing this extension | set `"selfEdit": true` in the global config |
| Private `/tmp` and no `/run/user` inside bwrap | tools that need a desktop/agent socket (`gh auth` via keyring, ssh-agent git push) | `bwrap.allowSockets`, or run them as `!` user commands |
| Project loosening ignored | repos that ship `mode: off` | set `allowProjectLoosening` globally |
| A malformed config → strict mode | anyone with a broken file | fix the file; `/sandbox status` shows where |
| `tools.default` is now `"ask"` | users of extension and MCP tools; `pi -p` scripts using custom tools | answer "always" once, or list them in `tools.allow`; set `"tools": {"default": "allow"}` for the old behavior |
| New runtime deps: `web-tree-sitter`, `tree-sitter-bash` (~1.5 MB wasm) | install | `npm install` in the extension dir; if the wasm fails to load, bash degrades to ask (H2.8) |
| Nested commands in `$(…)`, backticks and subshells are checked | broad allows | an unlisted nested command now asks; a hard-denied one denies |

## Decisions (resolved 2026-11-10)

1. **Parser:** `tree-sitter-bash` through `web-tree-sitter` (wasm). The
   spike passed under Bun 1.4.4; H2.0 confirms it inside pi. Fallback: a
   hand-written lexer behind the same interface.
2. **`mode: off` vs bwrap:** independent switches. `mode: off` turns off the
   guardrail only; `--no-sandbox` turns off both (H4.7).
3. **Interpreter one-liners:** NEVER_AUTO, meaning always *ask*: never
   auto-allowed, never persisted as a prefix, not hard-denied (H1.3, H6.2).
4. **Default `tools.default`:** `"ask"` (H5.5).
5. **Env handling:** mask-based, with the extended default masks from
   H4.4. No allowlist mode.

## Definition of done

- Every F1–F14 row is a passing test (F13 and F14 in the bwrap integration suite).
- `npm run typecheck && bun test` is green and runs in CI or pre-commit.
- No path from "analysis unsure" leads to *allow* without bwrap active, which
  is enforced by the property test in H2.9.
- The README and examples describe the shipped behavior, including what
  bwrap does **not** isolate.
