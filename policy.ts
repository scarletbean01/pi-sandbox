import * as fs from "node:fs";
import * as path from "node:path";
import {
	canonicalArgv,
	checkArgv,
	isNeverAuto,
	matchCommandValue,
	type CommandPolicy,
	type Verdict,
} from "./commands";
import { NEVER_AUTO_COMMANDS, type SandboxConfig } from "./config";
import { checkPath, existsRelative, looksLikePath, matchesDeny, type PathAccess } from "./paths";
import { analyze, isDangerousAssignment, type Analysis, type Cmd, type PathRef } from "./shell";
import { expandTilde } from "./util";

export interface PolicyState {
	config: SandboxConfig;
	cwd: string;
	/** --no-sandbox per-invocation override. */
	disabled: boolean;
	/** Session-scoped approvals ("Allow for this session"). */
	onceCache: Set<string>;
	/** Approvals valid for the current tool call only ("Allow once"). */
	callApprovals?: Set<string>;
	/** bwrap layer state: active = wrapping confirmed working this session. */
	bwrap?: { active: boolean; autoAllow: boolean };
	/** Absolute patterns the agent may never write to (policy files, extension dir, git hooks). */
	protectedWrite?: string[];
}

export interface EvalResult {
	verdict: Verdict;
	kind?: "command" | "path" | "tool";
	/** Failing segment/form, normalized path, or tool name (shown in the ask dialog). */
	subject?: string;
	/** Proxy binary a command was unwrapped through, if any. */
	via?: string;
	/** Policy pattern that matched (deny only). */
	pattern?: string;
	/** Block reason sent to the LLM (deny only). */
	reason?: string;
	/** Approval-cache key for this ask (`seg:…`, `path:…`, `tool:…`, `cmd:…`). */
	onceKey?: string;
	/** Full bash command the ask belongs to. */
	fullCommand?: string;
	/** Why the analysis could not fully understand the subject (shown in the dialog). */
	opaque?: string;
	/** NEVER_AUTO form: no prefix option, never auto-allowed. */
	neverAuto?: boolean;
	/** False when "always allow" must not be offered (non-literal command, unknown path). */
	persistable?: boolean;
	/** The ask covers the whole command (parse error / unparseable) rather than one segment. */
	wholeCommand?: boolean;
	/** argv of the failing command (for prefix suggestions). */
	argv?: string[];
}

const FILE_TOOLS = new Set(["read", "write", "edit", "grep", "find", "ls"]);
export const BUILTIN_TOOLS = new Set(["bash", ...FILE_TOOLS]);

/** Binaries whose path arguments are only read. Everything else is treated as potentially writing. */
const READ_ONLY_BINARIES = new Set([
	"cat",
	"head",
	"tail",
	"less",
	"more",
	"wc",
	"ls",
	"grep",
	"egrep",
	"fgrep",
	"rg",
	"file",
	"stat",
	"diff",
	"cmp",
	"md5sum",
	"sha1sum",
	"sha256sum",
	"tree",
	"du",
	"df",
	"readlink",
	"realpath",
	"basename",
	"dirname",
	"bat",
	"nl",
	"od",
	"hexdump",
	"strings",
	"jq",
	"cd",
	"pwd",
	"echo",
	"printf",
	"test",
	"[",
]);

const MANY_MATCHES = 500;

function approved(state: PolicyState, key: string): boolean {
	return state.onceCache.has(key) || (state.callApprovals?.has(key) ?? false);
}

function expandGlob(value: string, base: string): string[] | "many" | undefined {
	try {
		const matches: string[] = [];
		for (const m of fs.globSync(value, { cwd: base })) {
			matches.push(path.resolve(base, m));
			if (matches.length > MANY_MATCHES) return "many";
		}
		return matches;
	} catch {
		return undefined;
	}
}

const PROTECTED_REASON = (p: string, pattern?: string) =>
	pattern?.startsWith("/dev/")
		? `Path "${p}" is a raw device; writes to it are never allowed`
		: `Path "${p}" is sandbox policy; edit it yourself or use /sandbox`;

function pathDenyReason(check: { subject?: string; pattern?: string; protected?: boolean }, via?: string): string {
	if (check.protected) return PROTECTED_REASON(check.subject ?? "", check.pattern);
	return `Path "${check.subject}"${via ? ` (${via})` : ""} matches deny pattern "${check.pattern}"`;
}

interface BashDetail {
	result: EvalResult;
	analysis: Analysis;
	/** Human-readable trace for /sandbox test. */
	notes: string[];
}

function nonLiteralReason(cmd: Cmd): string | undefined {
	const reasons = new Set<string>();
	for (const w of cmd.argv) for (const e of w.expansions) reasons.add(e);
	for (const a of cmd.assignments) for (const e of a.value.expansions) reasons.add(e);
	if (reasons.size === 0) return undefined;
	const list = [...reasons].map((r) => (r.length > 40 ? `${r.slice(0, 37)}…` : r));
	return `contains expansions the sandbox cannot resolve: ${list.join(", ")}`;
}

function dangerousAssignment(cmd: Cmd): string | undefined {
	return cmd.assignments.find((a) => isDangerousAssignment(a.name))?.name;
}

export function evaluateBashDetailed(command: string, state: PolicyState): BashDetail {
	const { config, cwd } = state;
	const notes: string[] = [];
	const analysis = analyze(command, cwd);
	const policy: CommandPolicy = {
		allow: config.commands.allow,
		deny: config.commands.deny,
		proxies: config.commands.proxies,
	};
	const exactKey = `cmd:${command}`;
	const protectedWrite = state.protectedWrite ?? [];

	type CmdInfo = {
		cmd: Cmd;
		values: string[];
		literal: boolean;
		neverAuto: boolean;
		check: ReturnType<typeof checkArgv>;
		reason?: string;
	};
	const infos: CmdInfo[] = [];

	// ---- 1. command denies (over every command, nested included) ----------
	for (const cmd of analysis.commands) {
		if (cmd.argv.length === 0) continue;
		const values = cmd.argv.map((w) => w.value);
		const texts = cmd.argv.map((w) => w.text);
		const danger = dangerousAssignment(cmd);
		const literal =
			analysis.parser &&
			cmd.argv.every((w) => w.literal) &&
			cmd.assignments.every((a) => a.value.literal) &&
			danger === undefined;

		let check = checkArgv(values, literal, policy);
		if (check.verdict !== "deny" && texts.some((t, i) => t !== values[i])) {
			const textCheck = checkArgv(texts, false, policy);
			if (textCheck.verdict === "deny") check = textCheck;
		}
		if (check.verdict === "deny") {
			notes.push(`deny: "${check.form}" matches "${check.pattern}"`);
			return {
				analysis,
				notes,
				result: {
					verdict: "deny",
					kind: "command",
					subject: check.form,
					via: check.via,
					pattern: check.pattern,
					reason: `Command "${check.form}" matches deny pattern "${check.pattern}"${cmd.nested ? " (nested command)" : ""}`,
					onceKey: exactKey,
				},
			};
		}
		const neverAuto = isNeverAuto(values, NEVER_AUTO_COMMANDS, config.commands.proxies);
		let reason = nonLiteralReason(cmd);
		if (danger) reason = `sets ${danger}, which changes how programs behave`;
		infos.push({ cmd, values, literal, neverAuto, check, reason });
		notes.push(
			`command${cmd.nested ? " (nested)" : ""}: ${values.join(" ")} → ${check.verdict}${check.pattern ? ` (${check.pattern})` : ""}${neverAuto ? " [never auto]" : ""}${literal ? "" : " [non-literal]"}`,
		);
	}

	// ---- 2. path analysis ---------------------------------------------------
	const pathAsks: EvalResult[] = [];
	const seenPathAsks = new Set<string>();
	const pushPathAsk = (ask: EvalResult) => {
		if (ask.onceKey && seenPathAsks.has(ask.onceKey)) return;
		if (ask.onceKey) seenPathAsks.add(ask.onceKey);
		pathAsks.push(ask);
	};

	for (const ref of analysis.paths) {
		const info = ref.cmd !== undefined ? analysis.commands[ref.cmd] : undefined;
		const infoEntry = info ? infos.find((i) => i.cmd === info) : undefined;
		const refCmdName = infoEntry ? canonicalArgv(infoEntry.values)[0] : undefined;
		const access: PathAccess =
			ref.source === "arg" && refCmdName && READ_ONLY_BINARIES.has(refCmdName) ? "read" : ref.access;
		const denyOrAsk = checkRef(ref, access, state, protectedWrite, notes);
		if (denyOrAsk?.verdict === "deny") return { analysis, notes, result: { ...denyOrAsk, onceKey: exactKey } };
		if (denyOrAsk?.verdict === "ask") pushPathAsk({ ...denyOrAsk, fullCommand: command });
	}

	// ---- 3. command asks ---------------------------------------------------
	const asks: EvalResult[] = [];
	if (analysis.opaque.length > 0 && !approved(state, exactKey)) {
		asks.push({
			verdict: "ask",
			kind: "command",
			subject: command,
			onceKey: exactKey,
			fullCommand: command,
			opaque: analysis.opaque.join("; "),
			wholeCommand: true,
			persistable: false,
		});
	}
	for (const info of infos) {
		let allowed = info.check.verdict === "allow";
		if (allowed && info.neverAuto) allowed = policy.allow.includes(info.values.join(" "));
		if (allowed) continue;
		const subject = info.literal ? info.check.form : info.cmd.text;
		const key = `seg:${subject}`;
		if (approved(state, key) || approved(state, exactKey)) continue;
		asks.push({
			verdict: "ask",
			kind: "command",
			subject,
			via: info.check.via,
			onceKey: key,
			fullCommand: command,
			opaque: info.reason,
			neverAuto: info.neverAuto,
			persistable: info.literal,
			argv: info.check.form.split(/\s+/).filter((t) => t.length > 0),
		});
	}
	// Deduplicate identical asks (same key).
	const pending: EvalResult[] = [];
	const seen = new Set<string>();
	for (const ask of [...asks, ...pathAsks]) {
		if (ask.onceKey && seen.has(ask.onceKey)) continue;
		if (ask.onceKey) seen.add(ask.onceKey);
		pending.push(ask);
	}

	// ---- 4. bwrap autoAllow: bash-derived asks run kernel-bounded ------------
	const autoAllow = state.bwrap?.active === true && state.bwrap.autoAllow;
	const remaining = autoAllow ? pending.filter((a) => a.neverAuto) : pending;
	if (remaining.length === 0) return { analysis, notes, result: { verdict: "allow", onceKey: exactKey } };
	notes.push(`ask: ${remaining.length} pending (${autoAllow ? "after bwrap auto-allow" : "no auto-allow"})`);
	return { analysis, notes, result: remaining[0] };
}

/** Check one path reference; returns a deny/ask result or undefined when fine. */
function checkRef(
	ref: PathRef,
	access: PathAccess,
	state: PolicyState,
	protectedWrite: string[],
	notes: string[],
): EvalResult | undefined {
	const { config } = state;
	const word = ref.word;

	if (!word.literal) {
		// Unresolvable redirect targets must reach the user; unresolvable arguments are
		// covered by the owning command's non-literal ask.
		if (ref.source !== "redirect") return undefined;
		const subject = word.text;
		const key = `pathx:${subject}`;
		if (approved(state, key)) return undefined;
		return {
			verdict: "ask",
			kind: "path",
			subject,
			onceKey: key,
			opaque: "redirect target is not statically known",
			persistable: false,
		};
	}

	const value = word.value;
	if (value.length === 0) return undefined;
	const base = ref.cwd;
	const absolute = value.startsWith("/") || value.startsWith("~");

	// Working directory unknown (after cd with a dynamic target, pushd, conditionals…).
	if (base === null && !absolute) {
		if (ref.source === "arg" && !looksLikePath(value)) {
			// A bare word: can only be judged by name against the deny patterns.
			const hit = matchesDeny(path.join("/__unknown_cwd__", value), config.paths.deny, state.cwd);
			if (hit) {
				return {
					verdict: "deny",
					kind: "path",
					subject: value,
					pattern: hit,
					reason: `Path "${value}" matches deny pattern "${hit}"`,
				};
			}
			return undefined;
		}
		const key = `pathx:?${value}`;
		if (approved(state, key)) return undefined;
		return {
			verdict: "ask",
			kind: "path",
			subject: value,
			onceKey: key,
			opaque: "the working directory is unknown at this point (after cd with a dynamic target, pushd or a conditional cd)",
			persistable: false,
		};
	}
	const dir = base ?? state.cwd;

	// Candidate rule for plain arguments (redirects and cd targets are always paths).
	if (ref.source === "arg") {
		const candidate =
			looksLikePath(value) ||
			existsRelative(value, dir) ||
			matchesDeny(path.resolve(dir, expandTilde(value)), config.paths.deny, state.cwd) !== undefined;
		if (!candidate) return undefined;
	}

	// Glob expansion (unquoted * ? [ ]): every match is checked.
	let targets = [value];
	if (word.glob) {
		const expanded = expandGlob(expandTilde(value), dir);
		if (expanded === "many") {
			const key = `pathx:many:${value}`;
			if (approved(state, key)) return undefined;
			return {
				verdict: "ask",
				kind: "path",
				subject: value,
				onceKey: key,
				opaque: `the glob matches more than ${MANY_MATCHES} files`,
				persistable: false,
			};
		}
		if (expanded && expanded.length > 0) targets = expanded;
	}

	let ask: EvalResult | undefined;
	for (const target of targets) {
		const check = checkPath(target, config.paths.allow, config.paths.deny, dir, { access, protectedWrite });
		notes.push(`path: ${check.subject} (${access}) → ${check.verdict}${check.pattern ? ` (${check.pattern})` : ""}`);
		if (check.verdict === "deny") {
			return {
				verdict: "deny",
				kind: "path",
				subject: check.subject,
				pattern: check.pattern,
				reason: pathDenyReason(check),
			};
		}
		if (check.verdict === "ask" && !ask) {
			const key = `path:${check.subject}`;
			if (!approved(state, key)) ask = { verdict: "ask", kind: "path", subject: check.subject, onceKey: key, persistable: true };
		}
	}
	return ask;
}

function evaluateBash(command: string, state: PolicyState): EvalResult {
	return evaluateBashDetailed(command, state).result;
}

/** Literal glob inputs that can only ever select denied files (e.g. grep glob ".env"). */
function globOnlyDenied(glob: string, root: string, state: PolicyState): string | undefined {
	const { deny } = state.config.paths;
	if (!/[*?[{]/.test(glob)) {
		const hit = matchesDeny(path.resolve(root, glob), deny, state.cwd);
		if (hit) return hit;
	}
	const bare = glob.replace(/^(\*\*\/)+/, "");
	for (const pattern of deny) {
		const base = pattern.replace(/^(\*\*\/)+/, "");
		if (base === bare) return pattern;
	}
	return undefined;
}

function evaluateFileTool(toolName: string, input: Record<string, unknown>, state: PolicyState): EvalResult {
	const raw = typeof input.path === "string" && input.path.length > 0 ? input.path : ".";
	const { config, cwd } = state;
	const access: PathAccess = toolName === "write" || toolName === "edit" ? "write" : "read";
	const pathCheck = checkPath(raw, config.paths.allow, config.paths.deny, cwd, {
		access,
		protectedWrite: state.protectedWrite,
	});
	const onceKey = `path:${pathCheck.subject}`;

	if (pathCheck.verdict === "deny") {
		return {
			verdict: "deny",
			kind: "path",
			subject: pathCheck.subject,
			pattern: pathCheck.pattern,
			reason: pathCheck.protected
				? PROTECTED_REASON(pathCheck.subject ?? "", pathCheck.pattern)
				: `Path "${pathCheck.subject}" (${toolName}) matches deny pattern "${pathCheck.pattern}"`,
			onceKey,
		};
	}

	// grep `glob` / find `pattern` that select only denied files.
	const globInput = toolName === "grep" ? input.glob : toolName === "find" ? input.pattern : undefined;
	if (typeof globInput === "string" && globInput.length > 0) {
		const hit = globOnlyDenied(globInput, pathCheck.subject ?? cwd, state);
		if (hit) {
			return {
				verdict: "deny",
				kind: "path",
				subject: globInput,
				pattern: hit,
				reason: `Glob "${globInput}" (${toolName}) selects only files matching deny pattern "${hit}"`,
				onceKey,
			};
		}
	}

	if (pathCheck.verdict === "ask" && !approved(state, onceKey)) {
		return { verdict: "ask", kind: "path", subject: pathCheck.subject, onceKey, persistable: true };
	}
	return { verdict: "allow", onceKey };
}

/**
 * Evaluate a tool call against the policy. Order: mode check → tools policy
 * (all tools) → command/path checks (built-ins only). For custom tools the
 * tools policy is the only check. Approvals (per-call and session) are
 * consulted before surfacing an ask verdict.
 */
export function evaluate(toolName: string, input: Record<string, unknown>, state: PolicyState): EvalResult {
	if (state.disabled || state.config.mode === "off") return { verdict: "allow" };

	// Tools policy: name-level gate for every tool.
	const { tools } = state.config;
	const toolMatch = matchCommandValue(toolName, tools.allow, tools.deny);
	if (toolMatch.verdict === "deny") {
		return {
			verdict: "deny",
			kind: "tool",
			subject: toolName,
			pattern: toolMatch.pattern,
			reason: `Tool "${toolName}" matches deny pattern "${toolMatch.pattern}"`,
		};
	}

	if (!BUILTIN_TOOLS.has(toolName)) {
		// Custom tool: the tools policy is the only check.
		if (toolMatch.verdict === "allow") return { verdict: "allow" };
		const onceKey = `tool:${toolName}`;
		if (tools.default === "ask" && !approved(state, onceKey)) {
			return { verdict: "ask", kind: "tool", subject: toolName, onceKey, persistable: true };
		}
		return { verdict: "allow" };
	}

	if (toolName === "bash") {
		const command = typeof input.command === "string" ? input.command : "";
		return evaluateBash(command, state);
	}

	return evaluateFileTool(toolName, input, state);
}

/** Dry run for /sandbox test: verdict plus the reasoning trace. */
export function explain(toolName: string, input: Record<string, unknown>, state: PolicyState): { result: EvalResult; lines: string[] } {
	const lines: string[] = [];
	if (state.disabled || state.config.mode === "off") {
		lines.push("guardrail is off (mode: off or --no-sandbox): everything is allowed");
		return { result: { verdict: "allow" }, lines };
	}
	if (toolName === "bash") {
		const command = typeof input.command === "string" ? input.command : "";
		const detail = evaluateBashDetailed(command, state);
		lines.push(`parser: ${detail.analysis.parser ? "tree-sitter-bash" : "UNAVAILABLE (fallback tokenizer)"}`);
		if (detail.analysis.opaque.length > 0) lines.push(`opaque: ${detail.analysis.opaque.join("; ")}`);
		lines.push(...detail.notes);
		const auto = state.bwrap?.active === true && state.bwrap.autoAllow;
		lines.push(`bwrap: ${state.bwrap?.active ? "active" : "inactive"}, autoAllow: ${auto ? "yes" : "no"}`);
		return { result: detail.result, lines };
	}
	const result = evaluate(toolName, input, state);
	if (result.pattern) lines.push(`pattern: ${result.pattern}`);
	return { result, lines };
}

