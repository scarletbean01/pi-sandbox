import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import picomatch from "picomatch";
import type { Verdict } from "./commands";

const MATCH_OPTS = { dot: true };

/** Deny wins over allow; unlisted means ask. Hierarchical glob semantics (`*` does not cross `/`, `**` does). */
function matchPathValue(value: string, allow: string[], deny: string[]): { verdict: Verdict; pattern?: string } {
	for (const pattern of deny) {
		if (picomatch.isMatch(value, pattern, MATCH_OPTS)) return { verdict: "deny", pattern };
	}
	for (const pattern of allow) {
		if (picomatch.isMatch(value, pattern, MATCH_OPTS)) return { verdict: "allow", pattern };
	}
	return { verdict: "ask" };
}

function expandTilde(p: string): string {
	if (p === "~") return os.homedir();
	if (p.startsWith("~/")) return path.join(os.homedir(), p.slice(2));
	return p;
}

/**
 * Normalize an actual path: expand ~, resolve against cwd, collapse ./..,
 * and canonicalize via realpath for existing paths (kills symlink aliases).
 * Non-existent paths (new files) fall back to the resolved absolute path.
 */
export function normalizePath(p: string, cwd: string): string {
	const abs = path.resolve(cwd, expandTilde(p));
	try {
		return fs.realpathSync(abs);
	} catch {
		return abs;
	}
}

/**
 * Normalize a policy pattern. Patterns starting with ** are kept relative
 * (any-depth matchers like `**\/.env` apply everywhere); everything else is
 * anchored to cwd so `./**` means the project subtree.
 */
export function normalizePattern(pattern: string, cwd: string): string {
	const expanded = expandTilde(pattern);
	if (expanded.startsWith("**/")) return expanded;
	if (path.isAbsolute(expanded)) return path.normalize(expanded);
	return path.resolve(cwd, expanded);
}

export interface PathCheck {
	verdict: Verdict;
	/** Normalized path that produced the verdict. */
	subject?: string;
	pattern?: string;
}

/** Check a single path against the policy. */
export function checkPath(
	p: string,
	allow: string[],
	deny: string[],
	cwd: string,
): PathCheck {
	const normalized = normalizePath(p, cwd);
	const normalizedAllow = allow.map((pat) => normalizePattern(pat, cwd));
	const normalizedDeny = deny.map((pat) => normalizePattern(pat, cwd));
	const { verdict, pattern } = matchPathValue(normalized, normalizedAllow, normalizedDeny);
	return { verdict, subject: normalized, pattern };
}

/**
 * Heuristically extract path-like tokens from a command segment: tokens
 * starting with /, ~, ., or containing a slash. `cd` arguments are always
 * treated as paths (bare `cd src` has no separator). Redirection prefixes
 * and quotes are stripped.
 */
export function extractPathTokens(segment: string): string[] {
	const tokens = segment.split(/\s+/).filter((t) => t.length > 0);
	const paths: string[] = [];
	const binary = tokens[0] ?? "";

	for (let i = 0; i < tokens.length; i++) {
		let token = tokens[i];
		// Strip redirection prefixes (>, >>, 2>, 2>>, <).
		token = token.replace(/^(?:\d?>>?|<)/, "");
		// Strip surrounding quotes.
		token = token.replace(/^['"]|['"]$/g, "");
		if (token.length === 0 || token.startsWith("-")) continue;

		const looksLikePath = token.startsWith("/") || token.startsWith("~") || token.startsWith(".") || token.includes("/");
		const isCdTarget = binary === "cd" && i > 0;
		if (looksLikePath || isCdTarget) paths.push(token);
	}
	return paths;
}
