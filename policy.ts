import { checkCommand, matchCommandValue, splitSegments, unwrapProxies, type Verdict } from "./commands";
import type { SandboxConfig } from "./config";
import { checkPath, extractPathTokens } from "./paths";

export interface PolicyState {
	config: SandboxConfig;
	cwd: string;
	/** --no-sandbox per-invocation override. */
	disabled: boolean;
	/** Session-scoped "allow once" cache (exact strings). */
	onceCache: Set<string>;
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
	/** Cache key for "allow once" (full command, normalized path, or tool name). */
	onceKey?: string;
}

const FILE_TOOLS = new Set(["read", "write", "edit", "grep", "find", "ls"]);
const BUILTIN_TOOLS = new Set(["bash", ...FILE_TOOLS]);

function evaluateBash(command: string, state: PolicyState): EvalResult {
	const onceKey = `cmd:${command}`;
	const { config, cwd } = state;

	// Command policy: every segment must pass (proxied segments checked in all unwrapped forms).
	const cmdCheck = checkCommand(command, config.commands);
	if (cmdCheck.verdict === "deny") {
		const failed = cmdCheck.form ?? cmdCheck.segment;
		return {
			verdict: "deny",
			kind: "command",
			subject: failed,
			via: cmdCheck.via,
			pattern: cmdCheck.pattern,
			reason: `Command segment "${failed}" matches deny pattern "${cmdCheck.pattern}"`,
			onceKey,
		};
	}

	// Path policy: path-like tokens in every segment (and unwrapped form) must pass.
	for (const segment of splitSegments(command)) {
		const { forms } = unwrapProxies(segment, config.commands.proxies);
		for (const form of forms) {
			for (const token of extractPathTokens(form)) {
				const pathCheck = checkPath(token, config.paths.allow, config.paths.deny, cwd);
				if (pathCheck.verdict === "deny") {
					return {
						verdict: "deny",
						kind: "path",
						subject: pathCheck.subject,
						pattern: pathCheck.pattern,
						reason: `Path "${pathCheck.subject}" matches deny pattern "${pathCheck.pattern}"`,
						onceKey,
					};
				}
				if (pathCheck.verdict === "ask" && !state.onceCache.has(`path:${pathCheck.subject}`)) {
					return {
						verdict: "ask",
						kind: "path",
						subject: pathCheck.subject,
						onceKey,
					};
				}
			}
		}
	}

	// A command-level ask is only surfaced after paths pass.
	if (cmdCheck.verdict === "ask" && !state.onceCache.has(onceKey)) {
		return { verdict: "ask", kind: "command", subject: cmdCheck.form, via: cmdCheck.via, onceKey };
	}

	return { verdict: "allow", onceKey };
}

function evaluateFileTool(toolName: string, input: Record<string, unknown>, state: PolicyState): EvalResult {
	const raw = typeof input.path === "string" && input.path.length > 0 ? input.path : ".";
	const { config, cwd } = state;
	const pathCheck = checkPath(raw, config.paths.allow, config.paths.deny, cwd);
	const onceKey = `path:${pathCheck.subject}`;

	if (pathCheck.verdict === "deny") {
		return {
			verdict: "deny",
			kind: "path",
			subject: pathCheck.subject,
			pattern: pathCheck.pattern,
			reason: `Path "${pathCheck.subject}" (${toolName}) matches deny pattern "${pathCheck.pattern}"`,
			onceKey,
		};
	}
	if (pathCheck.verdict === "ask" && !state.onceCache.has(onceKey)) {
		return { verdict: "ask", kind: "path", subject: pathCheck.subject, onceKey };
	}
	return { verdict: "allow", onceKey };
}

/**
 * Evaluate a tool call against the policy. Order: mode check → tools policy
 * (all tools) → command/path checks (built-ins only). For custom tools the
 * tools policy is the only check. Session "allow once" entries are consulted
 * before surfacing an ask verdict.
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
		if (tools.default === "ask" && !state.onceCache.has(onceKey)) {
			return { verdict: "ask", kind: "tool", subject: toolName, onceKey };
		}
		return { verdict: "allow" };
	}

	if (toolName === "bash") {
		const command = typeof input.command === "string" ? input.command : "";
		const onceKey = `cmd:${command}`;
		if (state.onceCache.has(onceKey)) return { verdict: "allow", onceKey };
		return evaluateBash(command, state);
	}

	return evaluateFileTool(toolName, input, state);
}
