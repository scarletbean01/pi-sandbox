import { spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import picomatch from "picomatch";
import { commandGlobToRegex } from "./commands";
import type { BwrapConfig } from "./config";
import { normalizePattern } from "./paths";
import { expandTilde, shq } from "./util";

export interface BwrapProbe {
	available: boolean;
	/** Why the probe failed (binary missing vs launch failure), for the degraded warning. */
	reason?: string;
	/** bwrap supports --disable-userns (>= 0.8) and the full-form launch worked with it. */
	disableUserns: boolean;
	version?: string;
}

/** Env vars always unset inside the sandbox (in addition to bwrap.maskEnv): sockets and multiplexer handles. */
export const ALWAYS_UNSET_ENV = [
	"SSH_AUTH_SOCK",
	"DBUS_SESSION_BUS_ADDRESS",
	"XDG_RUNTIME_DIR",
	"DISPLAY",
	"WAYLAND_DISPLAY",
	"TMUX",
	"TMUX_PANE",
	"STY",
	"ZELLIJ*",
	"KITTY_LISTEN_ON",
	"WEZTERM_*",
	"HERDR*",
	"HC_*",
	"GPG_AGENT_INFO",
];

/** Host socket files hidden with /dev/null. */
const SOCKET_FILES = ["/var/run/docker.sock", "/run/docker.sock", "/run/snapd.socket", "/run/snapd-snap.socket"];
/** Host directories hidden with a tmpfs (system service sockets). */
const SOCKET_DIRS = ["/run/dbus", "/run/podman", "/run/containerd", "/run/libvirt"];

let cachedProbe: BwrapProbe | undefined;

function parseVersion(text: string): [number, number, number] | undefined {
	const m = /(\d+)\.(\d+)(?:\.(\d+))?/.exec(text);
	return m ? [Number(m[1]), Number(m[2]), Number(m[3] ?? 0)] : undefined;
}

export interface ProbeInput {
	cfg: BwrapConfig;
	cwd: string;
	env: NodeJS.ProcessEnv;
	extras?: BwrapExtras;
}

/**
 * Probe bwrap availability: binary presence, then a launch of the FULL command
 * form (every bind, tmpfs and flag the real wrapper uses), so a mount the host
 * rejects (AppArmor, odd mounts) degrades up front instead of failing every
 * bash call. Without `input`, only a minimal launch is attempted. Cached per
 * process; call resetBwrapProbe() on session start / reload.
 */
export function probeBwrap(input?: ProbeInput): BwrapProbe {
	if (cachedProbe) return cachedProbe;

	const version = spawnSync("bwrap", ["--version"], { stdio: "pipe" });
	if (version.error || version.status !== 0) {
		cachedProbe = { available: false, reason: "bwrap binary not found", disableUserns: false };
		return cachedProbe;
	}
	const versionText = version.stdout?.toString().trim() ?? "";
	const parsed = parseVersion(versionText);
	const supportsDisable = parsed !== undefined && (parsed[0] > 0 || parsed[1] >= 8);

	const minimal = spawnSync("bwrap", ["--unshare-user", "--ro-bind", "/", "/", "--", "true"], { stdio: "pipe" });
	if (minimal.error || minimal.status !== 0) {
		const stderr = minimal.stderr?.toString().trim();
		cachedProbe = {
			available: false,
			reason: `bwrap launch failed${stderr ? `: ${stderr}` : ""} (user namespaces disabled?)`,
			disableUserns: false,
			version: versionText,
		};
		return cachedProbe;
	}

	if (!input) {
		cachedProbe = { available: true, disableUserns: false, version: versionText };
		return cachedProbe;
	}

	const attempt = (disableUserns: boolean) => {
		const cmd = buildBwrapCommand("true", input.cfg, input.cwd, input.env, { ...input.extras, disableUserns });
		return spawnSync("sh", ["-c", cmd], { stdio: "pipe", cwd: input.cwd });
	};

	if (supportsDisable) {
		const first = attempt(true);
		if (!first.error && first.status === 0) {
			cachedProbe = { available: true, disableUserns: true, version: versionText };
			return cachedProbe;
		}
	}
	const second = attempt(false);
	if (!second.error && second.status === 0) {
		cachedProbe = { available: true, disableUserns: false, version: versionText };
		return cachedProbe;
	}
	const stderr = second.stderr?.toString().trim();
	cachedProbe = {
		available: false,
		reason: `bwrap full-form launch failed${stderr ? `: ${stderr}` : ""}`,
		disableUserns: false,
		version: versionText,
	};
	return cachedProbe;
}

export function resetBwrapProbe(): void {
	cachedProbe = undefined;
}

// ---------------------------------------------------------------------------
// Private /tmp
// ---------------------------------------------------------------------------

let sessionTmpDir: string | undefined;

/** Per-session private directory bound onto /tmp inside the sandbox. */
export function ensureSessionTmp(): string {
	if (sessionTmpDir && fs.existsSync(sessionTmpDir)) return sessionTmpDir;
	sessionTmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "pi-sbx-"));
	return sessionTmpDir;
}

export function cleanupSessionTmp(): void {
	if (!sessionTmpDir) return;
	try {
		fs.rmSync(sessionTmpDir, { recursive: true, force: true });
	} catch {
		// best effort
	}
	sessionTmpDir = undefined;
}

// ---------------------------------------------------------------------------
// In-project secret masks (kernel mirror of paths.deny)
// ---------------------------------------------------------------------------

export interface ProjectMask {
	path: string;
	dir: boolean;
}

export interface MaskScan {
	masks: ProjectMask[];
	/** The scan stopped at the cap: some denied files may be unmasked. */
	capped: boolean;
}

const SCAN_MAX_DEPTH = 6;
const SCAN_MAX_HITS = 200;
const SCAN_SKIP = new Set(["node_modules", ".git"]);

/** Find files/dirs under cwd that match `paths.deny` so the kernel layer can mask them too. */
export function scanProjectMasks(cwd: string, deny: string[]): MaskScan {
	const matchers = deny.map((d) => {
		try {
			return picomatch(normalizePattern(d, cwd), { dot: true });
		} catch {
			return () => false;
		}
	});
	const hit = (abs: string) => matchers.some((m) => m(abs));
	const masks: ProjectMask[] = [];
	let capped = false;

	function walk(dir: string, depth: number): void {
		if (capped || depth > SCAN_MAX_DEPTH) return;
		let entries: fs.Dirent[];
		try {
			entries = fs.readdirSync(dir, { withFileTypes: true });
		} catch {
			return;
		}
		for (const entry of entries) {
			if (capped) return;
			if (SCAN_SKIP.has(entry.name)) continue;
			const abs = path.join(dir, entry.name);
			if (entry.isSymbolicLink()) continue;
			const isDir = entry.isDirectory();
			if (hit(abs) || (isDir && hit(`${abs}/`))) {
				if (masks.length >= SCAN_MAX_HITS) {
					capped = true;
					return;
				}
				masks.push({ path: abs, dir: isDir });
				continue; // masked dirs are not descended into
			}
			if (isDir) walk(abs, depth + 1);
		}
	}
	walk(cwd, 1);
	return { masks, capped };
}

// ---------------------------------------------------------------------------
// Command construction
// ---------------------------------------------------------------------------

export interface BwrapExtras {
	/** Private dir bound onto /tmp. Without it /tmp is an empty tmpfs. */
	sessionTmp?: string;
	/** In-project files/dirs to hide (see scanProjectMasks). */
	projectMasks?: ProjectMask[];
	/** Add --disable-userns (probe-confirmed). */
	disableUserns?: boolean;
}

function exists(p: string): boolean {
	try {
		fs.statSync(p);
		return true;
	} catch {
		return false;
	}
}

function realOrSelf(p: string): string {
	try {
		return fs.realpathSync(p);
	} catch {
		return p;
	}
}

/**
 * Build the bwrap-wrapped form of a bash command. The sandbox gets a
 * read-only root with writable cwd/allowWrite binds and a private /tmp;
 * host service sockets (user runtime dir, D-Bus, docker, podman, …) are
 * hidden; subpaths in `readOnly` stay read-only inside the writable cwd;
 * denyRead paths and in-project secret files are hidden (tmpfs over dirs,
 * /dev/null over files); maskEnv-matching and socket-pointing variables are
 * unset. Missing paths are skipped so a stale config never breaks the launch.
 */
export function buildBwrapCommand(
	original: string,
	cfg: BwrapConfig,
	cwd: string,
	env: NodeJS.ProcessEnv,
	extras: BwrapExtras = {},
): string {
	const args: string[] = [
		"bwrap",
		"--unshare-user",
		"--unshare-pid",
		"--unshare-ipc",
		"--unshare-uts",
		"--unshare-cgroup-try",
	];
	if (extras.disableUserns) args.push("--disable-userns");
	args.push(
		"--cap-drop",
		"ALL",
		"--die-with-parent",
		"--new-session",
		"--ro-bind",
		"/",
		"/",
		"--dev",
		"/dev",
		"--proc",
		"/proc",
	);

	if (cfg.network === "off") args.push("--unshare-net");

	// Host service sockets: hide the user runtime dir (D-Bus user bus, systemd
	// user manager, pipewire, wayland, gpg-agent, keyring) and system sockets.
	const hidden = new Set<string>();
	const hideDir = (p: string) => {
		const real = realOrSelf(p);
		if (hidden.has(real)) return;
		try {
			if (fs.statSync(real).isDirectory()) {
				hidden.add(real);
				args.push("--tmpfs", shq(real));
			}
		} catch {
			// missing
		}
	};
	const hideFile = (p: string) => {
		const real = realOrSelf(p);
		if (hidden.has(real)) return;
		try {
			if (!fs.statSync(real).isDirectory()) {
				hidden.add(real);
				args.push("--ro-bind", "/dev/null", shq(real));
			}
		} catch {
			// missing
		}
	};
	const uid = typeof process.getuid === "function" ? process.getuid() : undefined;
	if (uid !== undefined) hideDir(`/run/user/${uid}`);
	for (const d of SOCKET_DIRS) hideDir(d);
	for (const f of SOCKET_FILES) hideFile(f);

	// Private /tmp.
	if (extras.sessionTmp && exists(extras.sessionTmp)) args.push("--bind", shq(extras.sessionTmp), "/tmp");
	else args.push("--tmpfs", "/tmp");
	args.push("--setenv", "TMPDIR", "/tmp");

	// Writable binds: cwd and allowWrite.
	args.push("--bind", shq(cwd), shq(cwd));
	for (const entry of cfg.allowWrite) {
		const p = path.resolve(cwd, expandTilde(entry));
		try {
			if (fs.statSync(p).isDirectory()) args.push("--bind", shq(p), shq(p));
		} catch {
			// missing: skip
		}
	}

	// Read-only subpaths inside the writable cwd (git hooks, editor/CI config…).
	// Missing paths are skipped: binding over them would create stray mount-point files on the host.
	for (const entry of cfg.readOnly) {
		const p = path.resolve(cwd, entry);
		const rel = path.relative(cwd, p);
		if (rel.startsWith("..") || path.isAbsolute(rel)) continue;
		if (exists(p)) args.push("--ro-bind", shq(p), shq(p));
	}

	// Explicitly allowed host sockets, re-bound after the masks.
	for (const entry of cfg.allowSockets) {
		const p = path.resolve(cwd, expandTilde(entry));
		if (exists(p)) args.push("--bind", shq(p), shq(p));
	}

	for (const entry of cfg.denyRead) {
		const p = path.resolve(cwd, expandTilde(entry));
		try {
			const stat = fs.statSync(p);
			if (stat.isDirectory()) args.push("--tmpfs", shq(p));
			else args.push("--ro-bind", "/dev/null", shq(p));
		} catch {
			// missing: skip
		}
	}

	for (const mask of extras.projectMasks ?? []) {
		if (!exists(mask.path)) continue;
		if (mask.dir) args.push("--tmpfs", shq(mask.path));
		else args.push("--ro-bind", "/dev/null", shq(mask.path));
	}

	const unset = [...cfg.maskEnv, ...ALWAYS_UNSET_ENV];
	for (const name of Object.keys(env)) {
		if (unset.some((pattern) => commandGlobToRegex(pattern).test(name))) {
			args.push("--unsetenv", shq(name));
		}
	}

	args.push("--chdir", shq(cwd), "--", "sh", "-c", shq(original));
	return args.join(" ");
}
