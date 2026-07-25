import { spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { commandGlobToRegex } from "./commands";
import type { BwrapConfig } from "./config";

/** Shell single-quote escaping: ' → '\'' */
function shq(value: string): string {
	return `'${value.replace(/'/g, `'\\''`)}'`;
}

function expandTilde(p: string): string {
	if (p === "~") return os.homedir();
	if (p.startsWith("~/")) return path.join(os.homedir(), p.slice(2));
	return p;
}

export interface BwrapProbe {
	available: boolean;
	/** Why the probe failed (binary missing vs launch failure), for the degraded warning. */
	reason?: string;
}

let cachedProbe: BwrapProbe | undefined;

/**
 * Probe bwrap availability: binary presence plus a trivial namespaced launch
 * (catches kernels with unprivileged user namespaces disabled). Cached per
 * process; call resetBwrapProbe() on extension reload.
 */
export function probeBwrap(): BwrapProbe {
	if (cachedProbe) return cachedProbe;

	const version = spawnSync("bwrap", ["--version"], { stdio: "pipe" });
	if (version.error || version.status !== 0) {
		cachedProbe = { available: false, reason: "bwrap binary not found" };
		return cachedProbe;
	}

	const launch = spawnSync("bwrap", ["--unshare-user", "--ro-bind", "/", "/", "--", "true"], { stdio: "pipe" });
	if (launch.error || launch.status !== 0) {
		const stderr = launch.stderr?.toString().trim();
		cachedProbe = {
			available: false,
			reason: `bwrap launch failed${stderr ? `: ${stderr}` : ""} (user namespaces disabled?)`,
		};
		return cachedProbe;
	}

	cachedProbe = { available: true };
	return cachedProbe;
}

export function resetBwrapProbe(): void {
	cachedProbe = undefined;
}

/**
 * Build the bwrap-wrapped form of a bash command. The sandbox gets a
 * read-only root with writable cwd/$TMPDIR/allowWrite binds; denyRead paths
 * are hidden (tmpfs over dirs, /dev/null over files); maskEnv-matching
 * variables are unset. Missing allowWrite/denyRead paths are skipped so a
 * stale config never breaks the launch.
 */
export function buildBwrapCommand(
	original: string,
	cfg: BwrapConfig,
	cwd: string,
	env: NodeJS.ProcessEnv,
): string {
	const args: string[] = [
		"bwrap",
		"--unshare-user",
		"--unshare-pid",
		"--unshare-ipc",
		"--unshare-uts",
		"--die-with-parent",
		"--new-session",
		"--ro-bind",
		"/",
		"/",
		"--dev",
		"/dev",
		"--proc",
		"/proc",
	];

	if (cfg.network === "off") args.push("--unshare-net");

	// Writable binds: cwd and the session temp dir.
	args.push("--bind", shq(cwd), shq(cwd));
	const tmp = os.tmpdir();
	try {
		if (fs.existsSync(tmp)) args.push("--bind", shq(tmp), shq(tmp));
	} catch {
		// skip
	}

	for (const entry of cfg.allowWrite) {
		const p = path.resolve(cwd, expandTilde(entry));
		try {
			if (fs.statSync(p).isDirectory()) args.push("--bind", shq(p), shq(p));
		} catch {
			// missing: skip
		}
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

	for (const name of Object.keys(env)) {
		if (cfg.maskEnv.some((pattern) => commandGlobToRegex(pattern).test(name))) {
			args.push("--unsetenv", shq(name));
		}
	}

	args.push("--chdir", shq(cwd), "--", "sh", "-c", shq(original));
	return args.join(" ");
}
