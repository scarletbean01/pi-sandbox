import * as path from "node:path";
import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import { basename } from "./commands";
import { isDirectory } from "./paths";
import type { EvalResult } from "./policy";
import { escapeGlob } from "./util";

/**
 * Dialog choices. Scopes:
 *  - once    this tool call only
 *  - session the rest of the session (in-memory)
 *  - whole   every command-level ask in this exact command, this call only
 *  - exact / prefix / path / subtree / parent   persisted to the config file
 */
export type AskChoice = "once" | "session" | "whole" | "exact" | "prefix" | "path" | "subtree" | "parent" | "deny";

export interface AskOutcome {
	choice: AskChoice;
	/** Pattern to persist for exact/prefix/path/subtree/parent. */
	pattern?: string;
}

const ONCE = "Allow once (this tool call only)";
const SESSION = "Allow for this session";
const WHOLE = "Allow this whole command once";
const DENY = "Deny";

/** Binaries that can run arbitrary code from their arguments. */
const EXEC_CAPABLE = new Set([
	"npx",
	"npm",
	"pnpm",
	"yarn",
	"bunx",
	"bun",
	"node",
	"perl",
	"ruby",
	"sh",
	"bash",
	"make",
	"just",
	"git",
	"find",
	"sed",
	"awk",
	"xargs",
	"env",
	"docker",
	"kubectl",
	"ssh",
	"curl",
	"wget",
]);
const isExecCapable = (bin: string) => EXEC_CAPABLE.has(bin) || /^python[0-9.]*$/.test(bin);

/** Binaries whose first argument is a subcommand: prefixes keep it (`git status *`, not `git *`). */
const HAS_SUBCOMMANDS = new Set([
	"git",
	"npm",
	"pnpm",
	"yarn",
	"bun",
	"cargo",
	"docker",
	"kubectl",
	"go",
	"gh",
	"systemctl",
	"brew",
	"pip",
	"pip3",
	"deno",
	"dotnet",
	"make",
	"just",
	"rake",
]);
/** Subcommand runners whose two-token prefix still runs arbitrary project code. */
const RUNNERS = new Set(["npm", "pnpm", "yarn", "bun", "make", "just", "rake"]);

export interface PrefixSuggestion {
	pattern: string;
	/** Label the pattern with a "runs arbitrary code" warning. */
	warn: boolean;
}

/** Safer persisted prefix for an argv, or undefined when none should be offered (NEVER_AUTO, non-literal). */
export function suggestPrefix(argv: string[], neverAuto: boolean): PrefixSuggestion | undefined {
	if (neverAuto || argv.length === 0) return undefined;
	const bin = argv[0];
	const name = basename(bin);
	const sub = argv[1];
	if (HAS_SUBCOMMANDS.has(name) && sub !== undefined && !sub.startsWith("-") && /^[A-Za-z0-9_.:-]+$/.test(sub)) {
		return { pattern: `${bin} ${sub} *`, warn: RUNNERS.has(name) };
	}
	return { pattern: `${bin} *`, warn: isExecCapable(name) };
}

const WARN = " ⚠ runs arbitrary code";

function withBanner(banner: string | undefined, body: string): string {
	return banner ? `${banner}\n\n${body}` : body;
}

/** Show the failing segment inside the full command, marked ▶ like this ◀. */
export function markSegment(fullCommand: string | undefined, subject: string): string {
	if (!fullCommand || fullCommand === subject) return `  ${subject}`;
	const at = fullCommand.indexOf(subject);
	if (at < 0) return `  ${fullCommand}\n\n  segment: ${subject}`;
	const marked = `${fullCommand.slice(0, at)}▶ ${subject} ◀${fullCommand.slice(at + subject.length)}`;
	return marked
		.split("\n")
		.map((l) => `  ${l}`)
		.join("\n");
}

/** Ask the user about an unlisted command segment (or a whole opaque command). */
export async function askCommand(ctx: ExtensionContext, result: EvalResult, banner?: string): Promise<AskOutcome> {
	const subject = result.subject ?? "";
	const marker = result.via ? ` (via ${result.via})` : "";
	const why = result.opaque ? `\n\nWhy: ${result.opaque}` : "";
	const neverNote = result.neverAuto ? "\n\nThis form can run arbitrary code and always asks." : "";
	const title = result.wholeCommand ? `Command the sandbox cannot fully analyze${marker}:` : `Unknown command${marker}:`;

	const options: string[] = [ONCE, SESSION];
	const map = new Map<string, AskOutcome>([
		[ONCE, { choice: "once" }],
		[SESSION, { choice: "session" }],
		[DENY, { choice: "deny" }],
	]);

	if (!result.wholeCommand && result.fullCommand && result.fullCommand !== subject) {
		options.push(WHOLE);
		map.set(WHOLE, { choice: "whole" });
	}
	if (result.persistable && !result.wholeCommand) {
		const exactLabel = `Always allow "${subject}"`;
		options.push(exactLabel);
		map.set(exactLabel, { choice: "exact", pattern: subject });
		const prefix = suggestPrefix(result.argv ?? [], result.neverAuto === true);
		if (prefix) {
			const label = `Always allow "${prefix.pattern}"${prefix.warn ? WARN : ""}`;
			options.push(label);
			map.set(label, { choice: "prefix", pattern: prefix.pattern });
		}
	}
	options.push(DENY);

	const body = `${title}\n\n${markSegment(result.fullCommand, subject)}${why}${neverNote}\n\nAllow?`;
	const picked = await ctx.ui.select(withBanner(banner, body), options);
	return (picked !== undefined && map.get(picked)) || { choice: "deny" };
}

/** Ask the user about an unlisted custom tool. Exact-name allow only, no prefix option. */
export async function askTool(ctx: ExtensionContext, toolName: string, banner?: string): Promise<AskOutcome> {
	const exactLabel = `Always allow "${toolName}"`;
	const picked = await ctx.ui.select(withBanner(banner, `Unknown tool:\n\n  ${toolName}\n\nAllow?`), [
		ONCE,
		SESSION,
		exactLabel,
		DENY,
	]);
	if (picked === ONCE) return { choice: "once" };
	if (picked === SESSION) return { choice: "session" };
	if (picked === exactLabel) return { choice: "exact", pattern: toolName };
	return { choice: "deny" };
}

/** Persisted pattern choices for a path: a directory offers its subtree, a file its parent folder. */
export function pathPatterns(normalizedPath: string): { path: string; tree: string; treeKind: "subtree" | "parent" } {
	const literal = escapeGlob(normalizedPath);
	if (isDirectory(normalizedPath)) {
		return { path: literal, tree: `${literal}/**`, treeKind: "subtree" };
	}
	return { path: literal, tree: `${escapeGlob(path.dirname(normalizedPath))}/**`, treeKind: "parent" };
}

/** Ask the user about a path outside the allowed folders. */
export async function askPath(ctx: ExtensionContext, result: EvalResult, banner?: string): Promise<AskOutcome> {
	const subject = result.subject ?? "";
	const why = result.opaque ? `\n\nWhy: ${result.opaque}` : "";
	const options: string[] = [ONCE, SESSION];
	const map = new Map<string, AskOutcome>([
		[ONCE, { choice: "once" }],
		[SESSION, { choice: "session" }],
		[DENY, { choice: "deny" }],
	]);

	if (result.persistable !== false) {
		const patterns = pathPatterns(subject);
		const pathLabel = isDirectory(subject) ? "Always allow this folder only" : "Always allow this file";
		options.push(pathLabel);
		map.set(pathLabel, { choice: "path", pattern: patterns.path });
		const treeLabel =
			patterns.treeKind === "subtree"
				? `Always allow "${subject}/**"`
				: `Always allow the parent folder "${path.dirname(subject)}/**"`;
		options.push(treeLabel);
		map.set(treeLabel, { choice: patterns.treeKind, pattern: patterns.tree });
	}
	options.push(DENY);

	const cmdLine =
		result.fullCommand && result.fullCommand.length > 0 ? `\n\nin command:\n  ${result.fullCommand.split("\n")[0]}` : "";
	const body = `Path outside allowed folders:\n\n  ${subject}${why}${cmdLine}\n\nAllow?`;
	const picked = await ctx.ui.select(withBanner(banner, body), options);
	return (picked !== undefined && map.get(picked)) || { choice: "deny" };
}
