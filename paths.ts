import * as fs from "node:fs";
import * as path from "node:path";
import picomatch from "picomatch";
import type { Verdict } from "./commands";
import { expandTilde } from "./util";

const MATCH_OPTS = { dot: true };

/** How a path is about to be used. `unknown` (bash arguments) is treated as write for protection checks. */
export type PathAccess = "read" | "write" | "unknown";

/** Character devices that are always safe to read/write (after deny and protection checks). */
const SAFE_DEVICES = new Set(["/dev/null", "/dev/zero", "/dev/stdin", "/dev/stdout", "/dev/stderr", "/dev/tty", "/dev/urandom", "/dev/random"]);

const matcherCache = new Map<string, (s: string) => boolean>();

/** Drop cached matchers (call on config reload). */
export function clearPathMatcherCache(): void {
	matcherCache.clear();
}

function matcherFor(pattern: string): (s: string) => boolean {
	let m = matcherCache.get(pattern);
	if (!m) {
		try {
			m = picomatch(pattern, MATCH_OPTS);
		} catch {
			m = () => false;
		}
		matcherCache.set(pattern, m);
	}
	return m;
}

function matchesAny(value: string, patterns: string[]): string | undefined {
	for (const pattern of patterns) {
		if (matcherFor(pattern)(value)) return pattern;
	}
	return undefined;
}

/** Lexical absolute path: ~ expanded, resolved against cwd, ./.. collapsed. No filesystem access. */
export function lexicalPath(p: string, cwd: string): string {
	return path.resolve(cwd, expandTilde(p));
}

/**
 * Canonicalize an absolute path through symlinks even when the tail does not
 * exist yet: realpath the deepest existing ancestor and re-append the
 * missing remainder. (`link/newfile` where `link` → /outside resolves to
 * /outside/newfile.)
 */
export function realpathDeep(abs: string): string {
	try {
		return fs.realpathSync(abs);
	} catch {
		// fall through to the ancestor walk
	}
	const tail: string[] = [];
	let current = abs;
	for (;;) {
		const parent = path.dirname(current);
		if (parent === current) return abs;
		tail.unshift(path.basename(current));
		current = parent;
		try {
			return path.join(fs.realpathSync(current), ...tail);
		} catch {
			// keep walking up
		}
	}
}

/**
 * Normalize an actual path: expand ~, resolve against cwd, collapse ./.. and
 * canonicalize through symlinks (kills symlink aliases, including symlinked
 * parents of not-yet-existing files).
 */
export function normalizePath(p: string, cwd: string): string {
	return realpathDeep(lexicalPath(p, cwd));
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

/** Pattern variants: anchored at the lexical cwd and (if different) at its real path. */
function patternVariants(pattern: string, cwd: string, realCwd: string): string[] {
	const first = normalizePattern(pattern, cwd);
	if (realCwd === cwd) return [first];
	const expanded = expandTilde(pattern);
	if (expanded.startsWith("**/") || path.isAbsolute(expanded)) return [first];
	const second = path.resolve(realCwd, expanded);
	return second === first ? [first] : [first, second];
}

export interface PathCheck {
	verdict: Verdict;
	/** Normalized (real) path that produced the verdict. */
	subject?: string;
	pattern?: string;
	/** True when the deny came from the write-protected policy paths. */
	protected?: boolean;
}

export interface CheckPathOptions {
	access?: PathAccess;
	/** Absolute patterns that may never be written (see config.computeProtectedWritePaths). */
	protectedWrite?: string[];
}

/**
 * Check a single path against the policy. Deny is checked against both the
 * lexical and the real path (a deny on either wins); allow requires the
 * real path to match.
 */
export function checkPath(
	p: string,
	allow: string[],
	deny: string[],
	cwd: string,
	options: CheckPathOptions = {},
): PathCheck {
	const lexical = lexicalPath(p, cwd);
	const real = realpathDeep(lexical);
	const subject = real;

	if (options.access !== "read" && options.protectedWrite && options.protectedWrite.length > 0) {
		const hit = matchesAny(lexical, options.protectedWrite) ?? matchesAny(real, options.protectedWrite);
		if (hit) return { verdict: "deny", subject, pattern: hit, protected: true };
	}

	const realCwd = realpathDeep(cwd);
	const denyPatterns = deny.flatMap((pat) => patternVariants(pat, cwd, realCwd));
	const denyHit = matchesAny(real, denyPatterns) ?? (lexical !== real ? matchesAny(lexical, denyPatterns) : undefined);
	if (denyHit) return { verdict: "deny", subject, pattern: denyHit };

	if (SAFE_DEVICES.has(lexical)) return { verdict: "allow", subject: lexical };

	const allowPatterns = allow.flatMap((pat) => patternVariants(pat, cwd, realCwd));
	const allowHit = matchesAny(real, allowPatterns);
	if (allowHit) return { verdict: "allow", subject, pattern: allowHit };

	return { verdict: "ask", subject };
}

/** Does the path (lexical or real) match any deny pattern? */
export function matchesDeny(p: string, deny: string[], cwd: string): string | undefined {
	const lexical = lexicalPath(p, cwd);
	const real = realpathDeep(lexical);
	const realCwd = realpathDeep(cwd);
	const patterns = deny.flatMap((pat) => patternVariants(pat, cwd, realCwd));
	return matchesAny(real, patterns) ?? (lexical !== real ? matchesAny(lexical, patterns) : undefined);
}

/** Heuristic: does a command word look like a path? */
export function looksLikePath(word: string): boolean {
	return word.startsWith("/") || word.startsWith("~") || word.startsWith(".") || word.includes("/");
}

/** Does the file exist relative to cwd (lstat, so dangling symlinks count)? */
export function existsRelative(word: string, cwd: string): boolean {
	try {
		fs.lstatSync(path.resolve(cwd, expandTilde(word)));
		return true;
	} catch {
		return false;
	}
}

/** Directory test used by dialogs to decide between "subtree" and "parent folder". */
export function isDirectory(p: string): boolean {
	try {
		return fs.statSync(p).isDirectory();
	} catch {
		return false;
	}
}
