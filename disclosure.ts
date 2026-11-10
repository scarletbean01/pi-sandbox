import * as path from "node:path";
import { expandTilde } from "./util";

/**
 * Pure renderer for the per-turn "Operational radius" block appended to the
 * system prompt via `before_agent_start`. Must be deterministic with respect
 * to its inputs (no fs realpath, no timestamps, no onceCache, no counts in
 * output) so the block is byte-identical across turns when state is unchanged
 * — preserving prompt-cache stability.
 *
 * Pure function of:
 *   (state.config, state.cwd, state.disabled, state.bwrap.active, state.bwrap.autoAllow)
 * plus the per-layer deny arrays (built-in / global / project) needed for
 * deterministic capping. Input contracts: deny arrays are raw patterns; the
 * renderer returns an exact string for any given input.
 */

const MAX_DENIES_SHOWN = 12;

/** Literal, content-constant strings. Cached-stable. Cache-stable by construction. */
const HEADER_LINE =
	"Operational radius — obey it. `*` = one path segment, `**` = any depth, `~/` = home, `./` = <project root>. Denies are unbypassable; do not ask the user to lift them or seek workarounds.";
const NEGATED_LINE = "Sandbox is OFF — no radius is in force; operate freely.";
/** Guardrail (pattern policy) off, but bash is still wrapped in bwrap: the agent must not think it is unbounded. */
const GUARDRAIL_OFF_BWRAP_LINE =
	"Guardrail is OFF; bash still runs kernel-sandboxed (bounds: writes limited to the project directory and configured cache dirs; network: ";
const FOOTNOTE_LINE =
	"[Bash is kernel-sandboxed with auto-allow; unlisted bash path tokens may run without prompting, bounded by the sandbox.]";

const ALLOW_HEADING = "Operate within:";
const DENY_HEADING = "Do not touch:";

export interface DenyLayers {
	builtin: string[];
	global: string[];
	project: string[];
}

export interface RenderState {
	cwd: string;
	/** --no-sandbox: guardrail AND bwrap are both off. */
	disabled: boolean;
	/** `mode: off`: the pattern guardrail is off; bwrap (if active) still bounds bash. */
	guardrailOff?: boolean;
	/** bwrap network setting, shown in the bounds line when the guardrail is off. */
	bwrapNetwork?: "allow" | "off";
	pathsAllow: string[];
	denyLayers: DenyLayers;
	bwrapActive: boolean;
	bwrapAutoAllow: boolean;
}

/**
 * Resolve cwd-anchored patterns for display. Patterns starting with the
 * two-asterisk prefix, the tilde, and absolute paths pass through verbatim;
 * everything else (including dot-relative paths and `./foo/-style` globs) is
 * resolved against `cwd` via `path.resolve` (stable, NOT realpath, so
 * symlink flips do not churn the rendered block).
 */
function displayAllowPattern(pattern: string, cwd: string): string {
	if (pattern.startsWith("**/")) return pattern;
	if (pattern.startsWith("~/")) return pattern;
	if (path.isAbsolute(pattern)) return pattern.normalize("NFC");
	// Anything else — including `./**`, `./foo/**`, bare `foo/**` — is
	// relative; resolve against cwd.
	return path.resolve(cwd, expandTilde(pattern));
}

/** Render the allow list under the "Operate within:" heading. */
function renderAllows(state: RenderState): string {
	const lines: string[] = [];
	const seen = new Set<string>();
	for (const pattern of state.pathsAllow) {
		const rendered = displayAllowPattern(pattern, state.cwd);
		if (seen.has(rendered)) continue;
		seen.add(rendered);
		lines.push(`  ${rendered}`);
	}
	if (lines.length === 0) {
		// Defensive: defaults ensure at least `./**` is always present; this
		// only fires if a user explicitly wiped the merged allow list.
		return `${ALLOW_HEADING}\n  (none — every path will prompt)`;
	}
	return `${ALLOW_HEADING}\n${lines.join("\n")}`;
}

/**
 * Render the deny list with deterministic capping. Order is fixed:
 * built-in defaults → global config → project config. Project fills last
 * so truncation never pushes a built-in out of the visible block.
 *
 * `+N more` carries the exact remaining count so the renderer is content-
 * deterministic (the truncation position is derived from config length, not
 * wall-clock).
 */
function renderDenies(state: RenderState): string {
	const ordered: string[] = [];
	const seen = new Set<string>();
	for (const layer of [state.denyLayers.builtin, state.denyLayers.global, state.denyLayers.project]) {
		for (const pattern of layer) {
			if (seen.has(pattern)) continue;
			seen.add(pattern);
			ordered.push(pattern);
		}
	}

	if (ordered.length === 0) {
		// Should not happen given defaults, but keep the heading for honesty.
		return `${DENY_HEADING}\n  (none)`;
	}

	const shown = ordered.slice(0, MAX_DENIES_SHOWN);
	const remaining = ordered.length - shown.length;
	const lines = shown.map((p) => `  ${p}`);
	if (remaining > 0) {
		lines.push(`  (+${remaining} more from project/global config; run /sandbox list)`);
	}
	return `${DENY_HEADING}\n${lines.join("\n")}`;
}

/**
 * Render the full per-turn radius block. Returns the negated line when
 * enforcement is inactive; otherwise the active-radius block (header + allows
 * + denies + optional autoAllow footnote). Always returns a non-empty string
 * — the caller decides whether to append it.
 */
export function renderRadiusBlock(state: RenderState): string {
	if (state.disabled) return NEGATED_LINE;
	if (state.guardrailOff) {
		if (!state.bwrapActive) return NEGATED_LINE;
		return `${GUARDRAIL_OFF_BWRAP_LINE}${state.bwrapNetwork ?? "allow"}).`;
	}

	const parts: string[] = [HEADER_LINE, "", renderAllows(state), "", renderDenies(state)];

	if (state.bwrapActive && state.bwrapAutoAllow) {
		parts.push("", FOOTNOTE_LINE);
	}

	return parts.join("\n");
}
