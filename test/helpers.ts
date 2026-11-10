import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { computeProtectedWritePaths, mergeConfigs, type PartialConfig, type SandboxConfig } from "../config";
import type { PolicyState } from "../policy";

export interface StateOptions {
	cwd: string;
	/** Session approvals. */
	once?: string[];
	/** Per-call approvals. */
	call?: string[];
	bwrap?: { active: boolean; autoAllow: boolean };
	disabled?: boolean;
	selfEdit?: boolean;
}

/** Config used by the bypass corpus: a few broad allows over the defaults. */
export const CORPUS_CONFIG: PartialConfig = {
	commands: { allow: ["git *", "ls *", "cat *", "echo *"], deny: [] },
};

export function stateWith(partial: PartialConfig, opts: StateOptions): PolicyState {
	const config: SandboxConfig = mergeConfigs(partial, undefined, { cwd: opts.cwd });
	return {
		config,
		cwd: opts.cwd,
		disabled: opts.disabled ?? false,
		onceCache: new Set(opts.once ?? []),
		callApprovals: new Set(opts.call ?? []),
		bwrap: opts.bwrap ?? { active: false, autoAllow: config.bwrap.autoAllow },
		protectedWrite: computeProtectedWritePaths(opts.cwd, opts.selfEdit ?? false),
	};
}

export interface Fixture {
	/** Project directory (realpath'd). */
	cwd: string;
	/** A directory outside the project that `link` points to. */
	outside: string;
}

/**
 * Run `fn` inside a temp project holding: .env, server.pem, a `link` symlink to
 * an outside dir, .git/hooks/, .pi/sandbox.json, and a plain `src/main.ts`.
 */
export async function withTempProject<T>(fn: (fx: Fixture) => T | Promise<T>): Promise<T> {
	const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "pi-sbx-test-")));
	const cwd = path.join(root, "project");
	const outside = path.join(root, "outside");
	fs.mkdirSync(path.join(cwd, ".git", "hooks"), { recursive: true });
	fs.mkdirSync(path.join(cwd, ".pi"), { recursive: true });
	fs.mkdirSync(path.join(cwd, "src"), { recursive: true });
	fs.mkdirSync(outside, { recursive: true });
	fs.writeFileSync(path.join(cwd, ".env"), "SECRET=1\n");
	fs.writeFileSync(path.join(cwd, "server.pem"), "-----BEGIN-----\n");
	fs.writeFileSync(path.join(cwd, ".pi", "sandbox.json"), "{}\n");
	fs.writeFileSync(path.join(cwd, "src", "main.ts"), "export {};\n");
	fs.symlinkSync(outside, path.join(cwd, "link"));
	try {
		return await fn({ cwd, outside });
	} finally {
		fs.rmSync(root, { recursive: true, force: true });
	}
}
