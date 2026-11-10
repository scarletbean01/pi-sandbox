import * as fs from "node:fs";
import * as path from "node:path";
import { Text } from "@earendil-works/pi-tui";
import {
	createBashTool,
	createLocalBashOperations,
	type ExtensionAPI,
	type ExtensionContext,
	type ToolCallEventResult,
	type UserBashEventResult,
} from "@earendil-works/pi-coding-agent";
import { writeAudit, type AuditEntry } from "./audit";
import { askCommand, askPath, askTool, type AskOutcome } from "./ask";
import {
	buildBwrapCommand,
	cleanupSessionTmp,
	ensureSessionTmp,
	probeBwrap,
	resetBwrapProbe,
	scanProjectMasks,
	ALWAYS_UNSET_ENV,
	type BwrapExtras,
	type BwrapProbe,
	type ProjectMask,
} from "./bwrap";
import { clearMatcherCache, commandGlobToRegex } from "./commands";
import {
	ConfigWriteError,
	globalConfigPath,
	loadConfig,
	saveToConfig,
	type BwrapConfig,
	type LoadedConfig,
	type SandboxConfig,
} from "./config";
import { renderRadiusBlock } from "./disclosure";
import { filterListing, isFilteredTool, type TextBlock } from "./filter";
import { clearPathMatcherCache } from "./paths";
import { BUILTIN_TOOLS, evaluate, explain, type EvalResult, type PolicyState } from "./policy";
import { initShell, parserError, parserReady } from "./shell";
import { Mutex } from "./util";

const STATUS_KEY = "sandbox";
const MAX_ASK_ROUNDS = 64;
const SANDBOX_SUBCOMMANDS = ["on", "off", "status", "list", "test", "reload"];

export interface SandboxDeps {
	/** Policy evaluator (injectable so tests can prove the handler fails closed). */
	evaluate?: typeof evaluate;
}

export default function (pi: ExtensionAPI) {
	createSandboxExtension(pi);
}

export function createSandboxExtension(pi: ExtensionAPI, deps: SandboxDeps = {}): void {
	const evaluatePolicy = deps.evaluate ?? evaluate;
	let loaded: LoadedConfig | undefined;
	/** Session-wide approvals ("Allow for this session"). */
	let onceCache = new Set<string>();
	let trusted = false;
	let bwrapActive = false;
	let bwrapProbe: BwrapProbe | undefined;
	let bwrapToolRegistered = false;
	let degradedWarned = false;
	let parserWarned = false;
	/** Live bwrap settings read by the bash override (never captured from the first session). */
	let currentBwrapCfg: BwrapConfig | undefined;
	let projectMasks: ProjectMask[] = [];
	let masksCapped = false;
	/** /sandbox on|off without --persist applies to this session only. */
	let sessionMode: "enforce" | "off" | undefined;
	const askMutex = new Mutex();
	const watchers: fs.FSWatcher[] = [];
	const seenMtimes = new Map<string, number>();
	let reloadTimer: ReturnType<typeof setTimeout> | undefined;

	// Start loading the wasm parser right away; tool_call awaits it if it is still loading.
	void initShell();

	pi.registerFlag("no-sandbox", {
		description: "Disable the sandbox (guardrail AND bwrap) for this invocation (not persisted)",
		type: "boolean",
		default: false,
	});

	const noSandbox = () => pi.getFlag("no-sandbox") === true;

	function audit(entry: AuditEntry): void {
		if (loaded?.effective.audit) writeAudit(entry);
	}

	function mtimeOf(file: string): number {
		try {
			return fs.statSync(file).mtimeMs;
		} catch {
			return 0;
		}
	}

	function report(ctx: ExtensionContext, current: LoadedConfig): void {
		for (const err of current.errors) {
			const where = err.line > 0 ? ` (line ${err.line}, column ${err.column})` : "";
			const msg = `sandbox: CONFIG ERROR in ${err.file}${where}: ${err.message} — strict fail-closed mode in force`;
			audit({ tool: "config", verdict: "error", note: msg });
			if (ctx.hasUI) ctx.ui.notify(msg, "error");
		}
		for (const warning of current.warnings) {
			audit({ tool: "config", verdict: "ask", note: warning });
		}
		if (current.warnings.length > 0 && ctx.hasUI) {
			ctx.ui.notify(`sandbox: ${current.warnings.length} config warning(s):\n${current.warnings.join("\n")}`, "warning");
		}
	}

	function ensureLoaded(ctx: ExtensionContext): LoadedConfig {
		if (!loaded) {
			trusted = ctx.isProjectTrusted();
			loaded = loadConfig(ctx.cwd, trusted);
			seenMtimes.set(loaded.globalFile, mtimeOf(loaded.globalFile));
			seenMtimes.set(loaded.projectFile, mtimeOf(loaded.projectFile));
			report(ctx, loaded);
		}
		return loaded;
	}

	function effectiveMode(config: SandboxConfig): "enforce" | "off" {
		return sessionMode ?? config.mode;
	}

	function stateFor(ctx: ExtensionContext, callApprovals?: Set<string>): PolicyState {
		const current = ensureLoaded(ctx);
		return {
			config: sessionMode ? { ...current.effective, mode: sessionMode } : current.effective,
			cwd: ctx.cwd,
			disabled: noSandbox(),
			onceCache,
			callApprovals,
			bwrap: { active: bwrapActive, autoAllow: current.effective.bwrap.autoAllow },
			protectedWrite: current.protectedWrite,
		};
	}

	function updateStatus(ctx: ExtensionContext, config: SandboxConfig): void {
		if (!ctx.hasUI) return;
		const mode = noSandbox() ? "off (--no-sandbox)" : effectiveMode(config) + (sessionMode ? " (session)" : "");
		const bwrapMark = config.bwrap.enabled && !noSandbox() ? (bwrapActive ? "+bwrap" : "(bwrap!)") : "";
		const parserMark = parserReady() ? "" : " parser!";
		const text = loaded?.configError ? "sandbox: CONFIG ERROR" : `sandbox: ${mode}${bwrapMark}`;
		ctx.ui.setStatus(STATUS_KEY, `${text}${parserMark}`);
	}

	function bwrapExtras(): BwrapExtras {
		return {
			sessionTmp: ensureSessionTmp(),
			projectMasks,
			disableUserns: bwrapProbe?.disableUserns === true,
		};
	}

	function rescanMasks(ctx: ExtensionContext, config: SandboxConfig): void {
		projectMasks = [];
		masksCapped = false;
		if (!config.bwrap.enabled || !config.bwrap.maskProjectDenies) return;
		const scan = scanProjectMasks(ctx.cwd, config.paths.deny);
		projectMasks = scan.masks;
		masksCapped = scan.capped;
		if (scan.capped && ctx.hasUI) {
			ctx.ui.notify(
				`sandbox: project scan hit the ${scan.masks.length}-file cap; some files matching paths.deny are not masked inside bwrap`,
				"warning",
			);
		}
	}

	/** Probe bwrap (full command form) and register the sandboxed bash override (once per process). */
	function setupBwrap(ctx: ExtensionContext, cfg: BwrapConfig): void {
		bwrapActive = false;
		bwrapProbe = undefined;
		currentBwrapCfg = cfg;

		if (cfg.enabled) {
			resetBwrapProbe();
			const probe = probeBwrap({ cfg, cwd: ctx.cwd, env: process.env, extras: { sessionTmp: ensureSessionTmp(), projectMasks } });
			bwrapProbe = probe;
			bwrapActive = probe.available;
			if (!probe.available && ctx.hasUI && !degradedWarned) {
				degradedWarned = true;
				ctx.ui.notify(
					`sandbox: bwrap unavailable (${probe.reason}) — bash runs UNSANDBOXED (fallback: ${cfg.fallback})`,
					"warning",
				);
			}
		}

		if (bwrapToolRegistered) return;
		bwrapToolRegistered = true;
		const bashTool = createBashTool(ctx.cwd, {
			spawnHook: ({ command, cwd, env }) => {
				const live = currentBwrapCfg;
				// --no-sandbox or bwrap switched off: pass through unwrapped.
				if (!live || !live.enabled || noSandbox()) return { command, cwd, env };
				if (!bwrapActive) {
					if (live.fallback === "block") {
						throw new Error('sandbox: bwrap unavailable and bwrap.fallback is "block"');
					}
					return { command, cwd, env };
				}
				return { command: buildBwrapCommand(command, live, cwd, env, bwrapExtras()), cwd, env };
			},
		});
		pi.registerTool({
			...bashTool,
			execute: async (id, params, signal, onUpdate, _toolCtx) => bashTool.execute(id, params, signal, onUpdate),
		});
	}

	pi.on("user_bash", (_event, ctx): UserBashEventResult | undefined => {
		const cfg = ensureLoaded(ctx).effective.bwrap;
		if (!cfg.enabled || !cfg.userBash || !bwrapActive || noSandbox()) return undefined;
		const local = createLocalBashOperations();
		return {
			operations: {
				exec: (command, cwd, options) =>
					local.exec(buildBwrapCommand(command, cfg, cwd, options.env ?? process.env, bwrapExtras()), cwd, options),
			},
		};
	});

	async function persistAllow(
		ctx: ExtensionContext,
		kind: "command" | "path" | "tool",
		pattern: string,
		approvalKey: string | undefined,
		callApprovals: Set<string>,
	): Promise<void> {
		const current = ensureLoaded(ctx);
		try {
			// Check trust fresh: project trust may resolve after the config was loaded.
			const file = await saveToConfig(ctx.cwd, ctx.isProjectTrusted(), { kind, pattern });
			seenMtimes.set(file, mtimeOf(file));
			const list =
				kind === "command"
					? current.effective.commands.allow
					: kind === "path"
						? current.effective.paths.allow
						: current.effective.tools.allow;
			if (!list.includes(pattern)) list.push(pattern);
			if (ctx.hasUI) ctx.ui.notify(`sandbox: saved "${pattern}" to ${file}`, "info");
		} catch (err) {
			const msg = err instanceof ConfigWriteError ? err.message : `could not save: ${(err as Error).message}`;
			if (ctx.hasUI) ctx.ui.notify(`sandbox: ${msg}. Allowing this call only.`, "error");
			if (approvalKey) callApprovals.add(approvalKey);
		}
	}

	/** Handle an ask verdict; returns a block result or undefined to proceed (re-evaluate). */
	async function resolveAsk(
		ctx: ExtensionContext,
		toolName: string,
		result: EvalResult,
		callApprovals: Set<string>,
	): Promise<ToolCallEventResult | undefined> {
		const current = ensureLoaded(ctx);
		if (!ctx.hasUI) {
			const hint =
				result.kind === "tool"
					? ` — add it to tools.allow in ${globalConfigPath()} (or set tools.default to "allow")`
					: "";
			audit({ tool: toolName, verdict: "deny", kind: result.kind, subject: result.subject, note: "no UI for confirmation" });
			return { block: true, reason: `Not in allowlist: ${result.subject} (no UI for confirmation)${hint}` };
		}

		const banner = current.configError ? "⚠ CONFIG ERROR — strict mode in force (see /sandbox status)" : undefined;
		const key = result.onceKey;
		let outcome: AskOutcome;
		if (result.kind === "tool") outcome = await askTool(ctx, result.subject ?? "", banner);
		else if (result.kind === "command") outcome = await askCommand(ctx, result, banner);
		else outcome = await askPath(ctx, result, banner);

		audit({
			tool: toolName,
			verdict: outcome.choice === "deny" ? "deny" : "allow",
			kind: result.kind,
			subject: result.subject,
			choice: outcome.choice,
			bwrap: bwrapActive,
		});

		switch (outcome.choice) {
			case "once":
				if (key) callApprovals.add(key);
				return undefined;
			case "session":
				if (key) onceCache.add(key);
				return undefined;
			case "whole":
				callApprovals.add(`cmd:${result.fullCommand ?? ""}`);
				return undefined;
			case "exact":
			case "prefix":
			case "path":
			case "subtree":
			case "parent": {
				const kind = result.kind ?? "command";
				if (outcome.pattern) await persistAllow(ctx, kind, outcome.pattern, key, callApprovals);
				// The persisted pattern may not cover the exact subject (e.g. a parent folder); keep this call moving.
				if (key) callApprovals.add(key);
				return undefined;
			}
			default:
				return { block: true, reason: "Blocked by user" };
		}
	}

	async function handleToolCall(
		toolName: string,
		input: Record<string, unknown>,
		ctx: ExtensionContext,
	): Promise<ToolCallEventResult | undefined> {
		await initShell();
		const callApprovals = new Set<string>();

		// Parser unavailable and bwrap.fallback is "block": no bash without analysis.
		if (
			toolName === "bash" &&
			!parserReady() &&
			!noSandbox() &&
			effectiveMode(ensureLoaded(ctx).effective) === "enforce" &&
			ensureLoaded(ctx).effective.bwrap.fallback === "block"
		) {
			const reason = `sandbox: bash parser unavailable (${parserError() ?? "unknown"}) and bwrap.fallback is "block"`;
			audit({ tool: toolName, verdict: "deny", note: reason });
			return { block: true, reason };
		}

		// Re-evaluate after each ask resolution: an answer may reveal further unlisted
		// segments/paths in the same call.
		for (let i = 0; i < MAX_ASK_ROUNDS; i++) {
			const result = evaluatePolicy(toolName, input, stateFor(ctx, callApprovals));

			if (result.verdict === "allow") {
				if (i === 0) audit({ tool: toolName, verdict: "allow", bwrap: bwrapActive });
				return undefined;
			}

			if (result.verdict === "deny") {
				audit({ tool: toolName, verdict: "deny", kind: result.kind, subject: result.subject, pattern: result.pattern, via: result.via });
				if (ctx.hasUI) ctx.ui.notify(`sandbox: blocked ${toolName}: ${result.reason}`, "warning");
				return { block: true, reason: result.reason };
			}

			// Serialize dialogs (parallel tool calls) and re-check under the lock: an earlier
			// answer may already cover this call.
			const step = await askMutex.run(async (): Promise<ToolCallEventResult | undefined> => {
				const again = evaluatePolicy(toolName, input, stateFor(ctx, callApprovals));
				if (again.verdict === "allow") return undefined;
				if (again.verdict === "deny") {
					audit({ tool: toolName, verdict: "deny", kind: again.kind, subject: again.subject, pattern: again.pattern });
					return { block: true, reason: again.reason };
				}
				return resolveAsk(ctx, toolName, again, callApprovals);
			});
			if (step) return step;
		}

		return { block: true, reason: "sandbox: policy evaluation did not converge" };
	}

	pi.on("tool_call", async (event, ctx): Promise<ToolCallEventResult | undefined> => {
		try {
			return await handleToolCall(event.toolName, event.input as Record<string, unknown>, ctx);
		} catch (err) {
			const message = err instanceof Error ? err.message : String(err);
			audit({ tool: event.toolName, verdict: "error", note: message });
			try {
				if (ctx.hasUI) ctx.ui.notify(`sandbox: internal error: ${message} — blocked`, "error");
			} catch {
				// ignore UI failures while failing closed
			}
			return { block: true, reason: `sandbox: internal error (${message}), failing closed` };
		}
	});

	// H3: children of an allowed root must not leak denied files through grep/find/ls output.
	pi.on("tool_result", (event, ctx) => {
		if (!isFilteredTool(event.toolName) || event.isError) return undefined;
		const state = stateFor(ctx);
		if (state.disabled || state.config.mode === "off") return undefined;
		const outcome = filterListing(event.toolName, event.input, event.content as TextBlock[], state.config.paths.deny, ctx.cwd);
		if (!outcome) return undefined;
		audit({ tool: event.toolName, verdict: "allow", note: `${outcome.hidden} result lines hidden` });
		return { content: outcome.content as typeof event.content };
	});

	pi.on("before_agent_start", (event, ctx) => {
		// Per-turn: append the Operational radius block to the system prompt so
		// the agent proactively knows its operational radius. Returns the
		// *full* systemPrompt (concatenated) to preserve sibling extensions'
		// chained contributions — `before_agent_start` replaces, not appends.
		const state = stateFor(ctx);
		const text = renderRadiusBlock({
			cwd: state.cwd,
			// --no-sandbox turns off both layers; mode: off only the guardrail.
			disabled: state.disabled,
			guardrailOff: state.config.mode === "off",
			bwrapNetwork: state.config.bwrap.network,
			pathsAllow: state.config.paths.allow,
			denyLayers: ensureLoaded(ctx).denyLayers,
			bwrapActive: bwrapActive && !state.disabled,
			bwrapAutoAllow: state.config.bwrap.autoAllow,
		});
		return { systemPrompt: event.systemPrompt + "\n\n" + text };
	});

	/** One-time notice after the tools.default change (H5.5). */
	function maybeNoticeToolsDefault(ctx: ExtensionContext, current: LoadedConfig): void {
		if (!ctx.hasUI || current.globalSetsToolsDefault) return;
		const marker = path.join(path.dirname(globalConfigPath()), ".sandbox-tools-default-notice");
		if (fs.existsSync(marker)) return;
		try {
			const custom = pi
				.getAllTools()
				.map((t) => t.name)
				.filter((name) => !BUILTIN_TOOLS.has(name) && !current.effective.tools.allow.includes(name));
			if (custom.length > 0) {
				ctx.ui.notify(
					`sandbox: tools.default is now "ask". Custom tools registered here will prompt once: ${custom.join(", ")}.\n` +
						`Allow them with "tools": { "allow": [...] } in ${current.globalFile}, or set "tools": { "default": "allow" } for the old behavior.`,
					"info",
				);
			}
			fs.mkdirSync(path.dirname(marker), { recursive: true });
			fs.writeFileSync(marker, "shown\n");
		} catch {
			// notice is best-effort
		}
	}

	function stopWatchers(): void {
		for (const w of watchers.splice(0)) {
			try {
				w.close();
			} catch {
				// ignore
			}
		}
		if (reloadTimer) clearTimeout(reloadTimer);
		reloadTimer = undefined;
	}

	/** Reload config files, re-probe bwrap and re-scan masks (keeps session approvals). */
	async function reload(ctx: ExtensionContext, announce: boolean): Promise<void> {
		loaded = undefined;
		clearMatcherCache();
		clearPathMatcherCache();
		degradedWarned = false;
		const current = ensureLoaded(ctx);
		rescanMasks(ctx, current.effective);
		setupBwrap(ctx, current.effective.bwrap);
		updateStatus(ctx, current.effective);
		if (announce && ctx.hasUI) ctx.ui.notify("sandbox: config reloaded", "info");
	}

	function startWatchers(ctx: ExtensionContext): void {
		stopWatchers();
		const current = ensureLoaded(ctx);
		const files = [current.globalFile, current.projectFile];
		for (const file of files) {
			try {
				const dir = path.dirname(file);
				if (!fs.existsSync(dir)) continue;
				const watcher = fs.watch(dir, (_ev, name) => {
					if (name !== path.basename(file)) return;
					if (reloadTimer) clearTimeout(reloadTimer);
					reloadTimer = setTimeout(() => {
						// Ignore the extension's own writes: their mtimes are recorded when saving.
						if (mtimeOf(file) === seenMtimes.get(file)) return;
						void reload(ctx, true);
					}, 500);
				});
				watcher.on("error", () => undefined);
				watchers.push(watcher);
			} catch {
				// watching is best-effort
			}
		}
	}

	pi.on("session_start", async (_event, ctx) => {
		loaded = undefined;
		onceCache = new Set<string>();
		sessionMode = undefined;
		degradedWarned = false;
		parserWarned = false;
		clearMatcherCache();
		clearPathMatcherCache();
		cleanupSessionTmp();
		await initShell();
		const current = ensureLoaded(ctx);
		if (!parserReady() && ctx.hasUI && !parserWarned) {
			parserWarned = true;
			ctx.ui.notify(
				`sandbox: bash parser unavailable (${parserError() ?? "unknown"}) — every bash command will ask${current.effective.bwrap.fallback === "block" ? " (bash is blocked: bwrap.fallback is \"block\")" : ""}`,
				"warning",
			);
		}
		rescanMasks(ctx, current.effective);
		setupBwrap(ctx, current.effective.bwrap);
		updateStatus(ctx, current.effective);
		maybeNoticeToolsDefault(ctx, current);
		startWatchers(ctx);
	});

	pi.on("session_shutdown", () => {
		stopWatchers();
		cleanupSessionTmp();
	});

	pi.registerMessageRenderer("sandbox-policy", (message, _options, theme) => {
		const body = typeof message.content === "string" ? message.content : JSON.stringify(message.content);
		return new Text(`${theme.fg("accent", theme.bold("Sandbox policy"))}\n${body}`, 0, 0);
	});

	function send(content: string): void {
		pi.sendMessage({ customType: "sandbox-policy", display: true, content });
	}

	pi.registerCommand("sandbox", {
		description: "Manage sandbox policy: /sandbox on|off [--persist]|status|list|test <cmd>|reload",
		getArgumentCompletions: (argumentPrefix) =>
			SANDBOX_SUBCOMMANDS.filter((s) => s.startsWith(argumentPrefix)).map((s) => ({ value: s, label: s })),
		handler: async (args, ctx) => {
			const current = ensureLoaded(ctx);
			const tokens = args.trim().split(/\s+/).filter((t) => t.length > 0);
			const sub = tokens[0] ?? "";
			const rest = args.trim().slice(sub.length).trim();

			if (sub === "on" || sub === "off") {
				const mode = sub === "on" ? "enforce" : "off";
				const persist = tokens.includes("--persist");
				sessionMode = mode;
				updateStatus(ctx, current.effective);
				if (persist) {
					try {
						const file = await saveToConfig(ctx.cwd, ctx.isProjectTrusted(), { kind: "mode", mode }, "global");
						seenMtimes.set(file, mtimeOf(file));
						current.effective.mode = mode;
						sessionMode = undefined;
						updateStatus(ctx, current.effective);
						ctx.ui.notify(`sandbox: mode "${mode}" saved to ${file}`, "info");
					} catch (err) {
						ctx.ui.notify(`sandbox: ${(err as Error).message}`, "error");
					}
				} else {
					ctx.ui.notify(`sandbox: mode "${mode}" for this session only (use /sandbox ${sub} --persist to save it to ${globalConfigPath()})`, "info");
				}
				return;
			}

			if (sub === "reload") {
				await reload(ctx, true);
				return;
			}

			if (sub === "test") {
				if (rest.length === 0) {
					ctx.ui.notify("usage: /sandbox test <bash command>  |  /sandbox test read|write|edit|grep|find|ls <path>", "info");
					return;
				}
				await initShell();
				const first = rest.split(/\s+/)[0];
				const isFileTool = ["read", "write", "edit", "grep", "find", "ls"].includes(first);
				const toolName = isFileTool ? first : "bash";
				const body = isFileTool ? rest.slice(first.length).trim() : first === "bash" ? rest.slice(4).trim() : rest;
				const input = toolName === "bash" ? { command: body } : { path: body };
				const { result, lines } = explain(toolName, input, stateFor(ctx));
				send(
					[
						`${toolName}: ${toolName === "bash" ? body : body || "."}`,
						`verdict: ${result.verdict.toUpperCase()}${result.reason ? ` — ${result.reason}` : ""}${result.subject && result.verdict === "ask" ? ` — would ask about: ${result.subject}${result.opaque ? ` (${result.opaque})` : ""}` : ""}`,
						...lines.map((l) => `  ${l}`),
					].join("\n"),
				);
				return;
			}

			if (sub === "list") {
				const c = current.effective;
				const project = current.projectLayer;
				const tag = (list: string[], layer: string[] | undefined) =>
					list.map((p) => `  ${p}${layer?.includes(p) ? " (project)" : ""}`).join("\n") || "  (none)";
				const fmt = (title: string, list: string[], layer?: string[]) => `${title} (${list.length}):\n${tag(list, layer)}`;
				const masked = Object.keys(process.env)
					.filter((n) => [...c.bwrap.maskEnv, ...ALWAYS_UNSET_ENV].some((pat) => commandGlobToRegex(pat).test(n)))
					.sort();
				send(
					[
						`mode: ${effectiveMode(c)}${sessionMode ? " (session override)" : ""}`,
						`tools.default: ${c.tools.default}`,
						fmt("tools.allow", c.tools.allow, project?.tools?.allow),
						fmt("tools.deny", c.tools.deny, project?.tools?.deny),
						fmt("commands.proxies", c.commands.proxies),
						fmt("commands.allow", c.commands.allow, project?.commands?.allow),
						fmt("commands.deny", c.commands.deny, project?.commands?.deny),
						fmt("paths.allow", c.paths.allow, project?.paths?.allow),
						fmt("paths.deny", c.paths.deny, project?.paths?.deny),
						`bwrap: enabled=${c.bwrap.enabled} autoAllow=${c.bwrap.autoAllow} network=${c.bwrap.network} fallback=${c.bwrap.fallback} userBash=${c.bwrap.userBash} maskProjectDenies=${c.bwrap.maskProjectDenies}`,
						fmt("bwrap.allowWrite", c.bwrap.allowWrite, project?.bwrap?.allowWrite),
						fmt("bwrap.readOnly", c.bwrap.readOnly, project?.bwrap?.readOnly),
						fmt("bwrap.allowSockets", c.bwrap.allowSockets),
						fmt("bwrap.denyRead", c.bwrap.denyRead, project?.bwrap?.denyRead),
						fmt("bwrap.maskEnv", c.bwrap.maskEnv, project?.bwrap?.maskEnv),
						`env names masked right now (names only): ${masked.join(", ") || "(none)"}`,
						`project files masked inside bwrap: ${projectMasks.length}${masksCapped ? " (cap reached)" : ""}`,
						`selfEdit=${c.selfEdit} allowProjectLoosening=${c.allowProjectLoosening} audit=${c.audit}`,
					].join("\n"),
				);
				return;
			}

			// Default: status.
			const c = current.effective;
			const projectTrusted = ctx.isProjectTrusted();
			const lines = [
				`sandbox: ${noSandbox() ? "off (--no-sandbox)" : effectiveMode(c)}${sessionMode ? " (this session only)" : ""}`,
				`config: ${current.globalFile}${projectTrusted ? ` + ${current.projectFile}` : " (project untrusted)"}`,
				`tools: ${c.tools.allow.length} allow / ${c.tools.deny.length} deny (default: ${c.tools.default})`,
				`commands: ${c.commands.allow.length} allow / ${c.commands.deny.length} deny (proxies: ${c.commands.proxies.join(", ") || "none"})`,
				`paths: ${c.paths.allow.length} allow / ${c.paths.deny.length} deny`,
				`bwrap: ${c.bwrap.enabled ? (bwrapActive ? `active${bwrapProbe?.disableUserns ? " (+disable-userns)" : ""}` : `UNAVAILABLE - bash unsandboxed (${bwrapProbe?.reason ?? "unknown"})`) : "disabled"} (autoAllow: ${c.bwrap.autoAllow}, network: ${c.bwrap.network}, fallback: ${c.bwrap.fallback})`,
				`bash parser: ${parserReady() ? "tree-sitter-bash" : `UNAVAILABLE (${parserError() ?? "unknown"}) — every bash command asks`}`,
			];
			for (const err of current.errors) {
				lines.push(`CONFIG ERROR ${err.file}${err.line > 0 ? ` line ${err.line}, column ${err.column}` : ""}: ${err.message} (strict mode in force)`);
			}
			for (const w of current.warnings) lines.push(`warning: ${w}`);
			ctx.ui.notify(lines.join("\n"), current.configError ? "error" : "info");
		},
	});
}
