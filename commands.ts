export type Verdict = "allow" | "deny" | "ask";

/**
 * Translate a command glob to a regex. Command segments are not paths, so
 * `*` matches any characters (including slashes): `rm -rf *` must match
 * `rm -rf /tmp/x`. All other regex metacharacters are escaped. A trailing
 * " *" also matches the bare command (`git push *` denies bare `git push`),
 * since users write prefix patterns expecting them to cover the bare form.
 */
export function commandGlobToRegex(pattern: string): RegExp {
	const bareSuffix = pattern.endsWith(" *");
	const body = bareSuffix ? pattern.slice(0, -2) : pattern;
	const escaped = body.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*");
	return new RegExp(bareSuffix ? `^${escaped}( .*)?$` : `^${escaped}$`);
}

/**
 * Split a bash command string into segments on shell operators.
 * Best-effort string split, not a shell parser: subshells, command
 * substitution, and quoting are not deeply analyzed (guardrail threat model).
 */
export function splitSegments(command: string): string[] {
	return command
		.split(/&&|\|\||[;|]/)
		.map((s) => s.trim())
		.filter((s) => s.length > 0);
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

/** First token of a segment, used for "always allow <binary> *" choices. */
export function segmentBinary(segment: string): string {
	return segment.split(/\s+/)[0] ?? segment;
}

/**
 * Unwrap proxy binaries (e.g. rtk) from a segment. Returns all forms from
 * the full segment down to the innermost command, plus the first proxy
 * binary stripped. Proxy flags and env prefixes are not parsed; a segment
 * like `rtk --json git status` unwraps to `--json git status`, which will
 * simply not match allowlists and degrade to ask (fail-safe).
 */
export function unwrapProxies(segment: string, proxies: string[]): { forms: string[]; via?: string } {
	const forms = [segment];
	let current = segment;
	let via: string | undefined;
	for (let i = 0; i < 3; i++) {
		const binary = segmentBinary(current);
		if (!proxies.includes(binary)) break;
		const rest = current.slice(binary.length).trim();
		if (rest.length === 0) break;
		via = via ?? binary;
		current = rest;
		forms.push(current);
	}
	return { forms, via };
}

export interface CommandPolicy {
	allow: string[];
	deny: string[];
	proxies: string[];
}

export interface CommandCheck {
	verdict: Verdict;
	/** Original segment that produced a deny or ask verdict. */
	segment?: string;
	/** The unwrapped form that matched (deny) or the innermost form (ask). */
	form?: string;
	/** Proxy binary the segment was unwrapped through, if any. */
	via?: string;
	/** The policy pattern that matched (deny only). */
	pattern?: string;
}

/**
 * Evaluate every segment of a command. Proxied segments are checked in all
 * unwrapped forms: deny on ANY form wins (keeps `rtk *` viable as a kill
 * switch while still catching `rtk git push`), allow on ANY form passes
 * (so both `git status` and full-segment `rtk gain` entries work). A command
 * is allowed only if all segments pass; the first deny or ask short-circuits.
 */
export function checkCommand(command: string, policy: CommandPolicy): CommandCheck {
	for (const segment of splitSegments(command)) {
		const { forms, via } = unwrapProxies(segment, policy.proxies);

		for (const form of forms) {
			const { verdict, pattern } = matchCommandValue(form, [], policy.deny);
			if (verdict === "deny") return { verdict: "deny", segment, form, via, pattern };
		}

		let allowed = false;
		for (const form of forms) {
			if (matchCommandValue(form, policy.allow, []).verdict === "allow") {
				allowed = true;
				break;
			}
		}
		if (!allowed) return { verdict: "ask", segment, form: forms[forms.length - 1], via };
	}
	return { verdict: "allow" };
}
