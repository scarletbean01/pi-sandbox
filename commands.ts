export type Verdict = "allow" | "deny" | "ask";

const regexCache = new Map<string, RegExp>();

/** Drop cached matchers (call on config reload). */
export function clearMatcherCache(): void {
	regexCache.clear();
}

/**
 * Translate a command glob to a regex. Command segments are not paths, so
 * `*` matches any characters (including slashes and newlines): `rm -rf *`
 * must match `rm -rf /tmp/x`. All other regex metacharacters are escaped. A
 * trailing " *" also matches the bare command (`git push *` denies bare
 * `git push`), since users write prefix patterns expecting them to cover the
 * bare form. Compiled regexes are cached.
 */
export function commandGlobToRegex(pattern: string): RegExp {
	const cached = regexCache.get(pattern);
	if (cached) return cached;
	const bareSuffix = pattern.endsWith(" *");
	const body = bareSuffix ? pattern.slice(0, -2) : pattern;
	const escaped = body.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*");
	const regex = new RegExp(bareSuffix ? `^${escaped}( .*)?$` : `^${escaped}$`, "s");
	regexCache.set(pattern, regex);
	return regex;
}

/** Deny wins over allow; unlisted means ask. */
export function matchCommandValue(value: string, allow: string[], deny: string[]): { verdict: Verdict; pattern?: string } {
	for (const pattern of deny) {
		if (commandGlobToRegex(pattern).test(value)) return { verdict: "deny", pattern };
	}
	for (const pattern of allow) {
		if (commandGlobToRegex(pattern).test(value)) return { verdict: "allow", pattern };
	}
	return { verdict: "ask" };
}

/** First token of a segment. */
export function segmentBinary(segment: string): string {
	return segment.split(/\s+/)[0] ?? segment;
}

// ---------------------------------------------------------------------------
// Proxy unwrapping
// ---------------------------------------------------------------------------

/**
 * Unwrap proxy binaries (e.g. rtk) from an argv. Returns all forms from the
 * full argv down to the innermost command, plus the first proxy binary
 * stripped. Proxy flags are not parsed; `rtk --json git status` unwraps to
 * `--json git status`, which will not match allowlists and degrades to ask.
 */
export function unwrapProxyArgv(argv: string[], proxies: string[]): { forms: string[][]; via?: string } {
	const forms: string[][] = [argv];
	let current = argv;
	let via: string | undefined;
	for (let i = 0; i < 3; i++) {
		const binary = current[0];
		if (binary === undefined || !proxies.includes(binary)) break;
		const rest = current.slice(1);
		if (rest.length === 0) break;
		via = via ?? binary;
		current = rest;
		forms.push(current);
	}
	return { forms, via };
}

/** String variant of unwrapProxyArgv (whitespace split). */
export function unwrapProxies(segment: string, proxies: string[]): { forms: string[]; via?: string } {
	const argv = segment.split(/\s+/).filter((t) => t.length > 0);
	const { forms, via } = unwrapProxyArgv(argv, proxies);
	return { forms: forms.map((f) => f.join(" ")), via };
}

// ---------------------------------------------------------------------------
// Canonicalization (deny matching only)
// ---------------------------------------------------------------------------

const ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*=/;

/** Strip leading NAME=value words. */
export function stripAssignments(argv: string[]): string[] {
	let i = 0;
	while (i < argv.length && ASSIGNMENT.test(argv[i])) i++;
	return argv.slice(i);
}

export function basename(word: string): string {
	const i = word.lastIndexOf("/");
	return i >= 0 ? word.slice(i + 1) : word;
}

/**
 * If argv[0] is a transparent wrapper, return argv without the wrapper and its
 * own options; otherwise undefined. Over-stripping is harmless here: the
 * result is only used to look for deny matches.
 */
function stripOneWrapper(argv: string[]): string[] | undefined {
	const name = basename(argv[0] ?? "");
	let i = 1;
	const takesValue = (opts: string[]) => (w: string) => opts.includes(w);
	switch (name) {
		case "env": {
			const withValue = takesValue(["-u", "--unset", "-C", "--chdir", "-S", "--split-string"]);
			while (i < argv.length) {
				const w = argv[i];
				if (w === "--") {
					i++;
					break;
				}
				if (ASSIGNMENT.test(w) || w === "-i" || w === "-0" || w === "-v" || /^--(ignore-environment|null|debug)$/.test(w)) {
					i++;
					continue;
				}
				if (withValue(w)) {
					i += 2;
					continue;
				}
				if (w.startsWith("-") && w.length > 1) {
					i++;
					continue;
				}
				break;
			}
			break;
		}
		case "command":
		case "builtin":
		case "nohup":
		case "setsid":
		case "time": {
			while (i < argv.length && argv[i].startsWith("-") && argv[i] !== "-") {
				if (argv[i] === "--") {
					i++;
					break;
				}
				i++;
			}
			break;
		}
		case "exec": {
			while (i < argv.length && argv[i].startsWith("-")) i += argv[i] === "-a" ? 2 : 1;
			break;
		}
		case "nice": {
			while (i < argv.length && argv[i].startsWith("-")) i += argv[i] === "-n" || argv[i] === "--adjustment" ? 2 : 1;
			break;
		}
		case "timeout": {
			while (i < argv.length && argv[i].startsWith("-")) i += argv[i] === "-s" || argv[i] === "-k" ? 2 : 1;
			i++; // duration
			break;
		}
		case "stdbuf": {
			while (i < argv.length && argv[i].startsWith("-")) {
				i += /^-[ioe]$/.test(argv[i]) ? 2 : 1;
			}
			break;
		}
		case "chrt": {
			while (i < argv.length && argv[i].startsWith("-")) i++;
			i++; // priority
			break;
		}
		case "ionice": {
			while (i < argv.length && argv[i].startsWith("-")) i += /^-[cnp]$/.test(argv[i]) ? 2 : 1;
			break;
		}
		default:
			return undefined;
	}
	if (i >= argv.length) return undefined;
	return argv.slice(i);
}

const SHELLS = new Set(["sh", "bash", "zsh", "dash", "ksh", "fish", "ash"]);

/** Normalize argv for `rm`: collapse flags to `-rf` when both recursive and force are present. */
function canonicalRm(argv: string[]): string[] | undefined {
	let recursive = false;
	let force = false;
	const rest: string[] = [];
	let endOfFlags = false;
	for (const w of argv.slice(1)) {
		if (!endOfFlags && w === "--") {
			endOfFlags = true;
			continue;
		}
		if (!endOfFlags && w.startsWith("--")) {
			if (w === "--recursive") recursive = true;
			else if (w === "--force") force = true;
			continue;
		}
		if (!endOfFlags && w.startsWith("-") && w.length > 1) {
			if (/[rR]/.test(w)) recursive = true;
			if (/f/.test(w)) force = true;
			continue;
		}
		rest.push(w);
	}
	if (!recursive || !force) return undefined;
	return ["rm", "-rf", ...rest];
}

/** Normalize shell invocations that carry -c in a flag cluster (`bash -xc id`) to `bash -c ...`. */
function canonicalShell(argv: string[]): string[] | undefined {
	for (let i = 1; i < argv.length; i++) {
		const w = argv[i];
		if (!w.startsWith("-") || w === "--") break;
		if (!w.startsWith("--") && w.includes("c")) return [basename(argv[0]), "-c", ...argv.slice(i + 1)];
	}
	return undefined;
}

/**
 * All argv variants to test against deny patterns: the raw argv, the argv with
 * leading assignments and transparent wrappers stripped at each level, with
 * argv0 reduced to its basename, plus shell `-c` and `rm -rf` normalizations.
 * Proxy-unwrapped variants of each are included.
 */
export function denyForms(argv: string[], proxies: string[]): string[] {
	const out = new Set<string>();
	const seen = new Set<string>();

	function addVariants(candidate: string[]): void {
		if (candidate.length === 0) return;
		const key = candidate.join("\u0000");
		if (seen.has(key)) return;
		seen.add(key);
		const { forms } = unwrapProxyArgv(candidate, proxies);
		for (const form of forms) {
			out.add(form.join(" "));
			const bin = basename(form[0] ?? "");
			const baseForm = [bin, ...form.slice(1)];
			out.add(baseForm.join(" "));
			if (bin === "rm") {
				const rm = canonicalRm(baseForm);
				if (rm) out.add(rm.join(" "));
			}
			if (SHELLS.has(bin)) {
				const sh = canonicalShell(baseForm);
				if (sh) out.add(sh.join(" "));
			}
			// Recurse through wrappers and proxies.
			const unassigned = stripAssignments(form);
			if (unassigned.length !== form.length) addVariants(unassigned);
			const unwrapped = stripOneWrapper(unassigned);
			if (unwrapped) addVariants(unwrapped);
		}
	}

	addVariants(argv);
	return [...out];
}

/** Canonical (wrapper-free) argv: used for display and NEVER_AUTO matching. */
export function canonicalArgv(argv: string[]): string[] {
	let current = stripAssignments(argv);
	for (let i = 0; i < 8; i++) {
		const next = stripOneWrapper(current);
		if (!next) break;
		current = stripAssignments(next);
	}
	if (current.length === 0) return current;
	return [basename(current[0]), ...current.slice(1)];
}

/** Forms tested against the NEVER_AUTO list: raw, wrapper-stripped, proxy-unwrapped. */
export function neverAutoForms(argv: string[], proxies: string[]): string[] {
	return denyForms(argv, proxies);
}

// ---------------------------------------------------------------------------
// Whole-argv checks
// ---------------------------------------------------------------------------

export interface CommandPolicy {
	allow: string[];
	deny: string[];
	proxies: string[];
}

export interface ArgvCheck {
	verdict: Verdict;
	/** The form that matched (deny) or the innermost form (ask). */
	form: string;
	via?: string;
	pattern?: string;
}

/**
 * Check one command's argv. Deny on ANY canonical form wins. Allow requires
 * the RAW argv (or a proxy-unwrapped form of it) to match an allow pattern
 * and every word to be literal: matching allows on the wrapper-stripped form
 * would let `/tmp/evil/git status` match `git *`.
 */
export function checkArgv(argv: string[], literal: boolean, policy: CommandPolicy): ArgvCheck {
	const { forms: rawForms, via } = unwrapProxyArgv(argv, policy.proxies);
	const innermost = rawForms[rawForms.length - 1].join(" ");

	for (const form of denyForms(argv, policy.proxies)) {
		const { verdict, pattern } = matchCommandValue(form, [], policy.deny);
		if (verdict === "deny") return { verdict: "deny", form, via, pattern };
	}

	if (literal) {
		for (const form of rawForms) {
			if (matchCommandValue(form.join(" "), policy.allow, []).verdict === "allow") {
				return { verdict: "allow", form: innermost, via };
			}
		}
	}
	return { verdict: "ask", form: innermost, via };
}

/** Whole-string variant of checkArgv for a whitespace-tokenized command. */
export function checkSegment(segment: string, policy: CommandPolicy): ArgvCheck {
	const argv = segment.split(/\s+/).filter((t) => t.length > 0);
	return checkArgv(argv, true, policy);
}

/** True when any form of the command matches a NEVER_AUTO pattern. */
export function isNeverAuto(argv: string[], patterns: string[], proxies: string[]): boolean {
	for (const form of neverAutoForms(argv, proxies)) {
		for (const pattern of patterns) {
			if (commandGlobToRegex(pattern).test(form)) return true;
		}
	}
	return false;
}
