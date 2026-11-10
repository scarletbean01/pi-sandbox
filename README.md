# sandbox

Guardrails for [pi](https://github.com/earendil-works/pi-mono). This extension
decides **which bash commands** the agent can run, **which folders** it can
read, write or search, and **which tools** it can call. It uses an allowlist,
a denylist, and a prompt for everything in between.

**Threat model: guardrails, not a security boundary.** The goal is to stop an
LLM from *accidentally* doing something bad: `rm -rf` in the wrong folder,
writing to `.env`, pushing to origin. The pattern checks are best effort. For a
real boundary on bash, use the bwrap layer (see below).

**The rule behind everything:** when the sandbox is not sure what a command
does, it **asks**. It never silently allows.

## How a tool call is checked

1. **Mode.** If `mode` is `"off"`, or you started pi with `--no-sandbox`, the
   guardrail allows everything. (See "Turning it off" for how this works with bwrap.)
2. **Tool name.** The name is checked against `tools.deny`, then `tools.allow`.
   For custom tools (MCP or other extensions) this is the only check. A tool in
   neither list follows `tools.default`, which is now **`"ask"`**.
3. **Bash commands.** The command is parsed with **tree-sitter-bash** (wasm).
   The sandbox checks *every* command it finds, not just the first one. That
   includes:
   - commands joined with `&&`, `||`, `;`, `|` and a single `&`
   - commands inside `$(...)`, backticks and `<(...)`
   - subshells, `if` / `for` / `while` / `case` bodies and function bodies

   Each command goes through deny, then allow, then ask.
   - **Deny** patterns also match disguised forms: `/bin/bash -c`, `env sh -c`,
     `nice sudo`, `rm -fr /`, `bash -xc`, and commands behind a proxy like `rtk`.
   - **Allow** patterns only match the plain, fully known command. So
     `/tmp/evil/git status` does not match `git *`.
4. **Paths.** The sandbox collects every path it can find and checks it against
   `paths.deny`, then `paths.allow`. For the file tools that is the `path`
   argument. For bash it also includes:
   - normal arguments and `--option=value` values
   - bare words that exist on disk or match a deny rule (`cat server.pem`)
   - redirect targets (`> file`) and `cd` targets
   - globs (`.en?` is expanded and each match is checked)
   - quotes and variables (`".e"nv` is `.env`, `$HOME` is your home folder)

   After a `cd`, later relative paths are resolved from the new folder.
   Symlinks are followed. A symlink inside the project that points outside it
   will ask, even for a file that does not exist yet.
5. **Self-protection.** The agent can **never write** these (reading is fine):
   - `~/.pi/agent/sandbox.json` and `<project>/.pi/sandbox.json`, plus their
     `.bak` and `.tmp` files
   - this extension's own folder (unless the global config has `selfEdit: true`)
   - `.git/hooks` and `.git/config`
   - raw disk devices like `/dev/sda`

   A project config cannot change this.
6. **Result filtering.** `grep`, `find` and `ls` only get their *root* path
   checked before they run. So their output is cleaned afterwards: any line that
   names a file matching `paths.deny` is removed, and the agent sees
   `[sandbox: N results hidden by deny policy]`. A `grep` glob or `find` pattern
   that can only match denied files (like `glob: ".env"`) is blocked up front.

**What the sandbox treats as "not sure":** `$VAR`, `$(...)`, `{a,b}`, a syntax
error, a grammar node it does not know, `PATH=...` style assignments,
`source $FILE`. These can never match an allow rule, so they ask. The dialog
tells you why. A command like `git log $(id)` gives you two prompts: one for
`id` and one for the outer command.

**Verdicts:**
- **deny**: blocked, and the agent sees the reason.
- **allow**: runs.
- **ask**: you get a prompt. In non-interactive runs (`pi -p`, RPC without UI)
  an ask means **blocked**.

If the extension hits an internal error, the call is **blocked** and you are
notified (fail closed). Your own `!` and `!!` commands are not checked by the
guardrail.

### Always denied

These cannot be overridden by any config:

- `eval`
- `bash`, `sh`, `zsh`, `dash`, `ksh`, `fish` with `-c`, and `busybox sh`
- `sudo`, `doas`, `su`, `pkexec`, `run0`
- `rm -rf` on `/`, `~`, `/*`, `~/*`
- `mkfs*`, `dd of=/dev/*`, `chmod -R` or `chown -R` on `/`
- writes to raw devices

### Always asks

These can run any code you hand them, so they **always ask**. An allow pattern
like `python3 *` does not match them. `autoAllow` does not skip them. The
dialog does not offer a "prefix" choice for them.

- `python -c` / `python -m`, `node -e` / `--eval` / `-p`, `perl -e`, `ruby -e`,
  `bun -e`, `deno eval`
- `xargs`
- `find ... -exec` / `-execdir` / `-ok` / `-delete`
- `git -c`

Only an allow entry that is *exactly* the whole command can match these.

### If the parser cannot load

The parser is two wasm files in `node_modules` (`web-tree-sitter` and
`tree-sitter-bash`). If they fail to load, the extension still works, but it
plays safe:

- **every bash command asks** (unless bwrap is on with `autoAllow`)
- deny rules still work, using a simple tokenizer
- the footer shows `parser!` and `/sandbox status` shows the reason
- with `bwrap.fallback: "block"`, bash is blocked instead

## What the agent is told

Every turn, the extension adds an **"Operational radius"** block to the system
prompt. It tells the agent where it may work and what it must not touch, so it
does not have to find out from block messages. It adds no new rules. It only
shows the existing config.

```
Operational radius — obey it. `*` = one path segment, `**` = any depth,
`~/` = home, `./` = <project root>. Denies are unbypassable; do not ask
the user to lift them or seek workarounds.

Operate within:
  /home/you/project/**
  ~/Projects/**

Do not touch:
  **/.env, **/.env.*, **/.git/**, **/.ssh/**, **/id_rsa*, **/*.pem
  (+N more from project/global config; run /sandbox list)
```

- Paths like `./**` are shown as full absolute paths.
- The deny list is capped. Built-in denies are always shown. Extra ones from
  global or project config are cut first, with an exact `+N more` count.
- If you run with `--no-sandbox`, or `mode: "off"` and no bwrap, the block is one
  line: `Sandbox is OFF — no radius is in force; operate freely.`
- If `mode: "off"` but bwrap is working, the agent is told the truth:
  `Guardrail is OFF; bash still runs kernel-sandboxed (bounds: ...)`.
- If bwrap and `autoAllow` are both on, a short note says that bash paths may
  run without a prompt because the kernel limits the damage.

The block is a snapshot from the start of the turn. If you click "Always allow"
mid-turn, enforcement changes right away, but the block updates next turn. This
can only make the agent more careful, never less.

## The bwrap layer (kernel boundary for bash)

The extension wraps **every bash command** in
[bubblewrap](https://github.com/containers/bubblewrap). The kernel enforces
these limits, so a clever command cannot get around them. The file tools run
inside pi itself and are **not** wrapped. For them, the guardrail is the only gate.

| What | Inside the sandbox |
|---|---|
| Root filesystem | read-only |
| Writable | the project folder, `bwrap.allowWrite` folders, and a **private `/tmp`** for this session (deleted when pi exits; `TMPDIR=/tmp`) |
| Read-only inside the project | `.git/hooks`, `.git/config`, `.git/info`, `.pi`, `.envrc`, `.vscode`, `.idea`, `.husky` (only if they exist; set with `bwrap.readOnly`) |
| Hidden credentials | everything in `bwrap.denyRead`: ssh, aws, gnupg, kube, docker, gh, git-credentials, netrc, npmrc, pypirc, cargo, gcloud, azure, password-store, keyrings, browser profiles, pi's `auth.json` |
| Secrets inside the project | files matching `paths.deny` look empty (`bwrap.maskProjectDenies`; scans up to 6 levels deep and 200 files, skips `node_modules` and `.git`; runs again on `/sandbox reload`) |
| Host sockets | hidden: `/run/user/$UID` (D-Bus, systemd user manager, pipewire, wayland, gpg-agent, keyring), `/run/dbus`, docker, podman, containerd, libvirt, snapd. Use the global-only `bwrap.allowSockets` to let one through |
| Environment variables | removed: names matching `bwrap.maskEnv` (like `AWS_*`, `*TOKEN*`, `*PASSWORD*`, `*_KEY`, `ANTHROPIC_*`, `OPENAI_*`), plus always `SSH_AUTH_SOCK`, `DBUS_SESSION_BUS_ADDRESS`, `XDG_RUNTIME_DIR`, `DISPLAY`, `WAYLAND_DISPLAY`, `TMUX*`, `STY`, `ZELLIJ*`, `KITTY_LISTEN_ON`, `WEZTERM_*`, `HERDR*`, `HC_*`, `GPG_AGENT_INFO`. `/sandbox list` shows which of your current variable *names* are masked (never the values) |
| Processes | separate user, pid, ipc, uts and cgroup namespaces; `--cap-drop ALL`; `--disable-userns` (bwrap 0.8 or newer); `--die-with-parent`; `--new-session` |
| Network | unchanged by default. `bwrap.network: "off"` turns it off with `--unshare-net` |

### What bwrap does NOT protect

- With `network: "allow"`, **abstract Unix sockets** (like `@/tmp/.X11-unix/X0`)
  are still reachable. Only `network: "off"` blocks them.
- Folders in `bwrap.allowWrite` are writable and the changes are visible
  outside. A writable `~/.cache` or `~/.npm` lets a command poison caches that
  other programs use. Use narrower entries if you care.
- The project folder is writable (except `bwrap.readOnly`). A command can edit
  source files, or create a missing `.envrc`. The kernel cannot protect a file
  that does not exist yet.
- The `read`, `write`, `edit`, `grep`, `find` and `ls` tools are not wrapped.
- If the network is on, a command can still send out anything it can read.

### Auto-allow

`bwrap.autoAllow: true` turns bash **asks** into silent allows, because the
kernel limits the damage anyway. It never overrides a deny, an always-ask form,
or a file-tool ask. It only works while bwrap is confirmed working. A project
config cannot turn it on.

### Probe and fallback

At session start (and on `/sandbox reload`) the extension test-runs the **full**
bwrap command, with every mount and flag. If the host rejects something
(AppArmor, odd mounts), you find out right away, not on every bash call.

If bwrap is missing or broken:
- `bwrap.fallback: "ask"` (default): bash runs with only the guardrail, with a
  visible warning and a `(bwrap!)` footer mark.
- `"block"`: bash is blocked.

The bash wrapper always reads the live config, so `/sandbox reload` takes effect
immediately.

### Turning it off

- `mode: "off"` turns off **only the guardrail**. Bash still runs inside bwrap.
- `bwrap.enabled: false` turns off bwrap.
- `pi --no-sandbox` turns off **both** for that run.

## Installation

The extension lives in `~/.pi/agent/extensions/sandbox/`. pi finds it
automatically, and `/reload` reloads it.

It needs these packages (all pinned): `picomatch`, `jsonc-parser`,
`web-tree-sitter` and `tree-sitter-bash`. The parser is about 1.5 MB of wasm.
There is no native build. If you copy the extension somewhere else, run this
inside the new folder:

```bash
npm install --ignore-scripts
```

## Configuration

Two config files. Both are optional, and both allow comments (JSONC):

| File | Scope | Used when |
|---|---|---|
| `~/.pi/agent/sandbox.json` | global | always |
| `<project>/.pi/sandbox.json` | project | only if the project is trusted |

Lists are joined (built-in defaults, then global, then project). Other settings
override. **A deny always wins**, so a project cannot remove a global or
built-in deny.

### A project config can only make things stricter

A cloned repo can ship a `.pi/sandbox.json`. So these project settings are
**ignored, with a warning**, unless your *global* config sets
`"allowProjectLoosening": true`:

- `mode: "off"`
- `bwrap.enabled: false`
- `bwrap.autoAllow: true`
- `bwrap.fallback: "ask"` when global says `"block"`
- `bwrap.network: "allow"` when global says `"off"`
- `tools.default: "allow"` when global says `"ask"`
- `bwrap.allowSockets`, `bwrap.allowWrite` outside the project, `selfEdit`, `audit`

Project **allow** lists still add on top, because that is what trusting a
project means. `/sandbox list` marks them `(project)`.

### A broken config fails closed

If a config file does not parse, the sandbox switches to **strict mode**:
`mode: enforce`, `tools.default: ask`, `autoAllow: false`,
`bwrap.fallback: block`, plus the built-in denies. You will see:

- `sandbox: CONFIG ERROR` in the footer
- a warning banner on every prompt
- the exact line and column in `/sandbox status`

Unknown keys, wrong types, bad values and patterns that do not compile give a
warning once per load. Fix the file, then run `/sandbox reload`. The files are
also watched, so saving a change reloads them.

### Saving from prompts

"Always allow ..." and `/sandbox off --persist` edit the file **in place**:

- comments and formatting are kept
- the write is atomic (temp file, fsync, rename)
- one `.bak` copy of the old file is kept
- if the file does not parse, the sandbox **refuses** to touch it

Allow patterns go to the project file when the project is trusted, otherwise to
the global file. `mode` always goes to the global file.

### Matching rules

**Command globs** (commands and tools): `*` matches any text, including
slashes. A trailing ` *` also matches the bare command, so `git push *` also
blocks plain `git push`. Examples: `git status` (exact), `npm *`, `ctx_*`.

**Path globs**: `*` stays inside one folder name. `**` goes any depth. `~` is
your home. Relative patterns start from the project folder (`./**` is the whole
project). Patterns starting with `**/` match anywhere (`**/.env`). Paths are
resolved through symlinks, even when the file does not exist yet. These are
always fine: `/dev/null`, `/dev/zero`, `/dev/std*`, `/dev/tty`, `/dev/urandom`,
`/dev/random`.

**Proxies.** If a command starts with a binary in `commands.proxies` (default
`rtk`), the sandbox strips it, up to 3 levels. Deny checks every form, and any
match blocks. Allow also checks every form. So `rtk git push` is caught by
`git push *`, and `rtk git status` passes through `git status`. Proxy flags are
not parsed, so those cases ask.

### Built-in defaults

- `paths.allow`: `["./**"]`
- `paths.deny`: `["**/.env", "**/.env.*", "**/.git/**", "**/.ssh/**", "**/id_rsa*", "**/*.pem"]`
- `commands.allow`: `[]`
- `commands.proxies`: `["rtk"]`
- `commands.deny`: the hard denies listed above
- `tools`: `{ allow: [], deny: [], default: "ask" }`
- `mode`: `"enforce"`

### Full reference

Every option, with comments, is in
[`examples/full-reference.sandbox.jsonc`](examples/full-reference.sandbox.jsonc).
The keys are `mode`, `selfEdit`, `allowProjectLoosening`, `audit`, `tools`,
`commands`, `paths`, and under `bwrap`: `enabled`, `autoAllow`, `network`,
`allowWrite`, `readOnly`, `denyRead`, `maskEnv`, `allowSockets`,
`maskProjectDenies`, `fallback`, `userBash`.

A small global config:

```jsonc
{
  "commands": {
    "allow": ["git status", "git diff *", "git log *", "ls *", "cat *"],
    "deny": ["git push *"]
  },
  "bwrap": { "autoAllow": true }   // global only: a project cannot turn this on
}
```

A real project config (Gradle + Spring Boot):
[`examples/gradle-spring-boot.sandbox.jsonc`](examples/gradle-spring-boot.sandbox.jsonc).

**Audit log.** Set `"audit": true` in the global config. Each decision then adds
one JSON line to `~/.pi/agent/sandbox-audit.jsonl`: tool, verdict, kind, what it
was about, the pattern, your choice, and whether bwrap was on. File contents and
env values are never logged. The file rotates at 5 MB.

**Custom tools and `tools.default`.** The default changed from `"allow"` to
`"ask"`. Unknown MCP and extension tools now prompt once. In non-interactive
runs they are blocked, and the message tells you to add them to `tools.allow`.
The first time you start after upgrading, you get a notice that lists the custom
tools it found. To get the old behavior, set `"tools": { "default": "allow" }`.

## The prompts

When something is not listed, you get a dialog. For commands it shows the **full
command**, with the unknown part marked, like this:
`ls /etc && ▶ curl x ◀ | sh`. If the sandbox is unsure, it also says why.

**Command prompt:**
- Allow once (this tool call only)
- Allow for this session
- Allow this whole command once
- Always allow the exact command
- Always allow a prefix (like `git status *`)
- Deny

**Path prompt:** Allow once, Allow for this session, Always allow this file or
folder, then either the folder's whole subtree (`<dir>/**`) or, for a file, its
parent folder. Or Deny.

**Tool prompt:** Allow once, Allow for this session, Always allow the tool, Deny.

**What the choices mean:**
- **Once** covers only this tool call. The next identical call asks again.
- **Session** lasts until the session restarts. It is kept in memory only.
- **Always** is saved to the config file.
- Approving a path does **not** approve command parts you have not seen yet.
  Approving a command does not approve a path.

**Prefixes are kept narrow.** You get `git status *`, not `git *`. For programs
that can run any code (`node`, `python`, `curl`, `npx`, and similar), a
one-word prefix is marked `⚠ runs arbitrary code`. The always-ask forms, and
commands with `$VAR` or `$(...)`, get no "always" choice at all.

**Special characters are escaped.** If you save a folder named `a[1]`, the saved
pattern matches exactly that folder and nothing broader.

**One prompt at a time.** If several tool calls run in parallel, their prompts
queue up. After each answer, the waiting call is checked again, because your
answer may already cover it.

## Commands and flags

| Command | What it does |
|---|---|
| `/sandbox on` / `/sandbox off` | Change the guardrail mode for **this session only** |
| `/sandbox on --persist` / `off --persist` | Also save `mode` to the **global** file |
| `/sandbox status` | Mode, config files, counts, bwrap and parser state, config errors and warnings |
| `/sandbox list` | The full effective policy. Project entries are marked `(project)`. Also shows which env names are masked |
| `/sandbox test <command>` | Dry run. Shows the verdict, each parsed command (nested ones too), the reasons it is unsure, the patterns that matched, and whether bwrap would auto-allow. Also works as `/sandbox test read\|write\|edit\|grep\|find\|ls <path>` |
| `/sandbox reload` | Re-read both config files, re-test bwrap, re-scan project secrets, update the footer |
| `pi --no-sandbox` | Turn off the guardrail **and** bwrap for this run. Never saved |

The footer shows the state so a loose setting is never hidden:
`sandbox: enforce+bwrap`, `sandbox: off`, `sandbox: CONFIG ERROR`, `(bwrap!)`
when bwrap is broken, and `parser!` when the bash parser did not load.

## Troubleshooting

**`bwrap unavailable (... user namespaces disabled?)` on Ubuntu 24.04+**
Ubuntu 24.04 limits user namespaces with AppArmor. Check with
`sysctl kernel.apparmor_restrict_unprivileged_userns` (`0` or "No such file"
means you are fine). The fix is to give bwrap its own profile:

```bash
sudo tee /etc/apparmor.d/bwrap > /dev/null << 'EOF'
abi <abi/4.0>,
include <tunables/global>

profile bwrap /usr/bin/bwrap flags=(unconfined) {
  userns,
  include if exists <local/bwrap>
}
EOF
sudo systemctl reload apparmor
```

**WSL**
- You need WSL2. WSL1 does not have the kernel features bwrap needs. Check with
  `wsl -l -v` in PowerShell, upgrade with `wsl --set-version <distro> 2`.
  The Ubuntu 24.04 AppArmor issue above also applies inside WSL2.
- Windows programs do not work inside the sandbox: `cmd.exe`, `powershell.exe`,
  and anything under `/mnt/c/*`. Watch out for WSL's `appendWindowsPath`, which
  can quietly turn a command like `code` into a `.exe`. Working in a
  `/mnt/c/...` folder is fine. Only running `.exe` files is blocked.

**A command fails with `Read-only file system`**
That is expected for writes outside the project, `/tmp` and `bwrap.allowWrite`.
Add the folder to `bwrap.allowWrite` if it is a build cache. The common ones
(`~/.gradle`, `~/.m2`, `~/.npm`, `~/.cache`) are already there.

**A tool that needs a desktop or agent socket stops working**
Things like `gh auth` through the keyring, `ssh-agent` for `git push`, `docker`,
or `tmux` need a host socket, and the sandbox hides those. Either list the socket
in the global `bwrap.allowSockets`, or run that command yourself with `!`.

**Something that needs `/tmp` from the host is missing**
Bash now gets a private, empty `/tmp`. Files created by other programs in the
host `/tmp` are not visible there.

**A secret is readable inside bwrap**
`bwrap.denyRead` hides only paths that exist when bash starts, and it matches the
exact path. New credential locations need their own entry. A typo in `denyRead`
is skipped silently, so check with `/sandbox list`.

**Every bash command asks, and the footer says `parser!`**
The wasm parser did not load. Run `/sandbox status` to see why. Usually
`npm install --ignore-scripts` in the extension folder fixes it.

**The agent cannot edit this extension's code**
That is on purpose. If you are developing the extension, set `"selfEdit": true`
in the **global** config.

## Notes for AI agents

If you are an AI agent running inside a sandboxed pi session:

- A block message like `Command "X" matches deny pattern "Y"` or
  `Path "P" matches deny pattern "Y"` is **final**. Do not try again with small
  changes (quoting, variables, `cd` chains). Ask the user to change the policy.
- Paths marked as "sandbox policy" cannot be edited by you. Tell the user what
  to change and let them do it.
- If you need something that is not listed, the user gets a prompt. Say clearly
  *why* you need it.
- Interpreters with inline code (`python3 -c`, `node -e`) always ask. That is on
  purpose.
- The **"Operational radius"** block in your system prompt is the rule. Stay
  inside the allow list. Never touch the deny list. Do not ask the user to
  lift a deny. If the block says the sandbox is OFF, there is no radius in force.
- If you edit `sandbox.json` by hand: comments are fine, keep denies for
  anything destructive, prefer narrow allows (`git status`) over wide ones
  (`git *`), and check with `/sandbox list` after `/sandbox reload`.

## Development

**Files:**

| File | Job |
|---|---|
| `index.ts` | wiring, prompts flow, `/sandbox` command |
| `policy.ts` | the decision engine |
| `shell.ts` | bash analysis with tree-sitter |
| `commands.ts` | command matching, canonical forms, proxies |
| `paths.ts` | path matching, symlink resolving |
| `filter.ts` | removes denied files from grep/find/ls output |
| `config.ts` | load, check, merge and save config |
| `ask.ts` | the dialogs |
| `bwrap.ts` | bubblewrap command, probe, project secret masks |
| `disclosure.ts` | the per-turn "Operational radius" block |
| `audit.ts`, `util.ts` | audit log, shared helpers |

**Checks:** run `npm run check`. It runs `npm run typecheck` and `bun test`. To
run it before every commit: `git config core.hooksPath .githooks`.

**Tests:**
- `test/bypass-corpus.test.ts` is a table of real bypass attempts and the verdict
  each must get. It only grows.
- `test/property.test.ts` mixes safe, unlisted and denied commands in many shell
  forms and checks that a denied part always denies and an unlisted part never
  allows.
- `test/bwrap.integration.test.ts` runs real bwrap. It skips itself if bwrap
  cannot run on the machine.

**Good to know:**
- pi loads extensions through jiti, so `import.meta.dirname` does not work. The
  extension folder is found with `__dirname` (see `util.ts`).
- Under pi, the agent cannot write this folder unless `selfEdit` is `true`.
- Design notes: [`PLAN.md`](PLAN.md) and [`HARDENING-PLAN.md`](HARDENING-PLAN.md).
