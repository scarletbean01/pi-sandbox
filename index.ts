import { Text } from "@earendil-works/pi-tui";
import {
	createBashTool,
	createLocalBashOperations,
	type ExtensionAPI,
	type ExtensionContext,
	type ToolCallEventResult,
	type UserBashEventResult,
} from "@earendil-works/pi-coding-agent";
import { askCommand, askPath, askTool } from "./ask";
import { buildBwrapCommand, probeBwrap, resetBwrapProbe } from "./bwrap";
import { segmentBinary } from "./commands";
import { loadConfig, saveToConfig, type BwrapConfig, type LoadedConfig, type SandboxConfig } from "./config";
import { evaluate, type EvalResult, type PolicyState } from "./policy";

const STATUS_KEY = "sandbox";

export default function (pi: ExtensionAPI) {
	let loaded: LoadedConfig | undefined;
	let onceCache = new Set<string>();
	let trusted = false;
	let bwrapActive = false;
	let bwrapToolRegistered = false;
	let degradedWarned = false;

	pi.registerFlag("no-sandbox", {
		description: "Disable the sandbox policy for this invocation (not persisted)",
		type: "boolean",
		default: false,
	});

	function ensureLoaded(ctx: ExtensionContext): LoadedConfig {
		if (!loaded) {
			trusted = ctx.isProjectTrusted();
			loaded = loadConfig(ctx.cwd, trusted);
			if (loaded.globalMalformed && ctx.hasUI) {
				ctx.ui.notify(`sandbox: malformed config ignored: ${loaded.globalFile}`, "error");
			}
			if (loaded.projectMalformed && ctx.hasUI) {
				ctx.ui.notify(`sandbox: malformed config ignored: ${loaded.projectFile}`, "error");
			}
		}
		return loaded;
	}

	function stateFor(ctx: ExtensionContext): PolicyState {
		const current = ensureLoaded(ctx);
		return {
			config: current.effective,
			cwd: ctx.cwd,
			disabled: pi.getFlag("no-sandbox") === true,
			onceCache,
			bwrap: { active: bwrapActive, autoAllow: current.effective.bwrap.autoAllow },
		};
	}

	function updateStatus(ctx: ExtensionContext, config: SandboxConfig): void {
		const disabled = pi.getFlag("no-sandbox") === true;
		const mode = disabled ? "off (--no-sandbox)" : config.mode;
		const bwrapMark = config.bwrap.enabled ? (bwrapActive ? "+bwrap" : "(bwrap!)") : "";
		ctx.ui.setStatus(STATUS_KEY, `sandbox: ${mode}${bwrapMark}`);
	}

	/** Probe bwrap and register the sandboxed bash override (once per session). */
	function setupBwrap(ctx: ExtensionContext, cfg: BwrapConfig): void {
		bwrapActive = false;
		if (!cfg.enabled) return;

		const probe = probeBwrap();
		bwrapActive = probe.available;
		if (!probe.available && ctx.hasUI && !degradedWarned) {
			degradedWarned = true;
			ctx.ui.notify(
				`sandbox: bwrap unavailable (${probe.reason}) — bash runs UNSANDBOXED (fallback: ${cfg.fallback})`,
				"warning",
			);
		}

		if (bwrapToolRegistered) return;
		bwrapToolRegistered = true;
		const bashTool = createBashTool(ctx.cwd, {
			spawnHook: ({ command, cwd, env }) => {
				if (!bwrapActive) {
					if (cfg.fallback === "block") {
						throw new Error('sandbox: bwrap unavailable and bwrap.fallback is "block"');
					}
					return { command, cwd, env };
				}
				return { command: buildBwrapCommand(command, cfg, cwd, env), cwd, env };
			},
		});
		pi.registerTool({
			...bashTool,
			execute: async (id, params, signal, onUpdate, _toolCtx) => bashTool.execute(id, params, signal, onUpdate),
		});
	}

	pi.on("user_bash", (event, ctx): UserBashEventResult | undefined => {
		const cfg = ensureLoaded(ctx).effective.bwrap;
		if (!cfg.enabled || !cfg.userBash || !bwrapActive) return undefined;
		const local = createLocalBashOperations();
		return {
			operations: {
				exec: (command, cwd, options) =>
					local.exec(buildBwrapCommand(command, cfg, cwd, options.env ?? process.env), cwd, options),
			},
		};
	});

	function persistAllow(
		ctx: ExtensionContext,
		kind: "command" | "path" | "tool",
		pattern: string,
	): void {
		const current = ensureLoaded(ctx);
		// Check trust fresh: project trust may resolve after the config was loaded.
		const file = saveToConfig(ctx.cwd, ctx.isProjectTrusted(), { kind, pattern });
		const list =
			kind === "command"
				? current.effective.commands.allow
				: kind === "path"
					? current.effective.paths.allow
					: current.effective.tools.allow;
		if (!list.includes(pattern)) list.push(pattern);
		if (ctx.hasUI) ctx.ui.notify(`sandbox: saved "${pattern}" to ${file}`, "info");
	}

	/** Handle an ask verdict; returns a block result or undefined to proceed. */
	async function resolveAsk(ctx: ExtensionContext, result: EvalResult): Promise<ToolCallEventResult | undefined> {
		if (!ctx.hasUI) {
			return { block: true, reason: `Not in allowlist: ${result.subject} (no UI for confirmation)` };
		}

		if (result.kind === "tool") {
			const toolName = result.subject ?? "";
			const choice = await askTool(ctx, toolName);
			if (choice === "once") {
				if (result.onceKey) onceCache.add(result.onceKey);
				return undefined;
			}
			if (choice === "exact") {
				persistAllow(ctx, "tool", toolName);
				return undefined;
			}
			return { block: true, reason: "Blocked by user" };
		}

		if (result.kind === "command") {
			const form = result.subject ?? "";
			const choice = await askCommand(ctx, form, result.via);
			if (choice === "once") {
				if (result.onceKey) onceCache.add(result.onceKey);
				return undefined;
			}
			if (choice === "exact") {
				persistAllow(ctx, "command", form);
				return undefined;
			}
			if (choice === "prefix") {
				persistAllow(ctx, "command", `${segmentBinary(form)} *`);
				return undefined;
			}
			return { block: true, reason: "Blocked by user" };
		}

		const subject = result.subject ?? "";
		const choice = await askPath(ctx, subject);
		if (choice === "once") {
			if (result.onceKey) onceCache.add(result.onceKey);
			return undefined;
		}
		if (choice === "path") {
			persistAllow(ctx, "path", subject);
			return undefined;
		}
		if (choice === "subtree") {
			persistAllow(ctx, "path", `${subject}/**`);
			return undefined;
		}
		return { block: true, reason: "Blocked by user" };
	}

	pi.on("tool_call", async (event, ctx): Promise<ToolCallEventResult | undefined> => {
		// Every tool call goes through the policy: the tools section gates by
		// name (custom tools included), built-ins continue to command/path checks.
		// Re-evaluate after each ask resolution: persisting one pattern may
		// reveal further unlisted segments/paths in the same call.
		for (let i = 0; i < 10; i++) {
			const result = evaluate(event.toolName, event.input as Record<string, unknown>, stateFor(ctx));

			if (result.verdict === "allow") return undefined;

			if (result.verdict === "deny") {
				if (ctx.hasUI) ctx.ui.notify(`sandbox: blocked ${event.toolName}: ${result.reason}`, "warning");
				return { block: true, reason: result.reason };
			}

			const askResult = await resolveAsk(ctx, result);
			if (askResult) return askResult;
		}

		return { block: true, reason: "sandbox: policy evaluation did not converge" };
	});

	pi.on("session_start", (_event, ctx) => {
		loaded = undefined;
		onceCache = new Set<string>();
		resetBwrapProbe();
		degradedWarned = false;
		const config = ensureLoaded(ctx).effective;
		setupBwrap(ctx, config.bwrap);
		updateStatus(ctx, config);
	});

	pi.registerMessageRenderer("sandbox-policy", (message, _options, theme) => {
		const body = typeof message.content === "string" ? message.content : JSON.stringify(message.content);
		return new Text(`${theme.fg("accent", theme.bold("Sandbox policy"))}\n${body}`, 0, 0);
	});

	pi.registerCommand("sandbox", {
		description: "Manage sandbox policy: /sandbox on|off|status|list",
		getArgumentCompletions: (argumentPrefix) =>
			["on", "off", "status", "list"]
				.filter((s) => s.startsWith(argumentPrefix))
				.map((s) => ({ value: s, label: s })),
		handler: async (args, ctx) => {
			const current = ensureLoaded(ctx);
			const sub = args.trim().split(/\s+/)[0] ?? "";

			if (sub === "on" || sub === "off") {
				const mode = sub === "on" ? "enforce" : "off";
				const file = saveToConfig(ctx.cwd, ctx.isProjectTrusted(), { kind: "mode", mode });
				current.effective.mode = mode;
				updateStatus(ctx, current.effective);
				ctx.ui.notify(`sandbox: mode "${mode}" saved to ${file}`, "info");
				return;
			}

			if (sub === "list") {
				const c = current.effective;
				const fmt = (title: string, list: string[]) =>
					`${title} (${list.length}):\n${list.map((p) => `  ${p}`).join("\n") || "  (none)"}`;
				pi.sendMessage({
					customType: "sandbox-policy",
					display: true,
					content: [
						`mode: ${c.mode}`,
						`tools.default: ${c.tools.default}`,
						fmt("tools.allow", c.tools.allow),
						fmt("tools.deny", c.tools.deny),
						fmt("commands.proxies", c.commands.proxies),
						fmt("commands.allow", c.commands.allow),
						fmt("commands.deny", c.commands.deny),
						fmt("paths.allow", c.paths.allow),
						fmt("paths.deny", c.paths.deny),
						`bwrap: enabled=${c.bwrap.enabled} autoAllow=${c.bwrap.autoAllow} network=${c.bwrap.network} fallback=${c.bwrap.fallback} userBash=${c.bwrap.userBash}`,
						fmt("bwrap.allowWrite", c.bwrap.allowWrite),
						fmt("bwrap.denyRead", c.bwrap.denyRead),
						fmt("bwrap.maskEnv", c.bwrap.maskEnv),
					].join("\n"),
				});
				return;
			}

			// Default: status.
			const c = current.effective;
			const disabled = pi.getFlag("no-sandbox") === true;
			const projectTrusted = ctx.isProjectTrusted();
			ctx.ui.notify(
				[
					`sandbox: ${disabled ? "off (--no-sandbox)" : c.mode}`,
					`config: ${current.globalFile}${projectTrusted ? ` + ${current.projectFile}` : " (project untrusted)"}`,
					`tools: ${c.tools.allow.length} allow / ${c.tools.deny.length} deny (default: ${c.tools.default})`,
					`commands: ${c.commands.allow.length} allow / ${c.commands.deny.length} deny (proxies: ${c.commands.proxies.join(", ") || "none"})`,
					`paths: ${c.paths.allow.length} allow / ${c.paths.deny.length} deny`,
					`bwrap: ${c.bwrap.enabled ? (bwrapActive ? "active" : "UNAVAILABLE - bash unsandboxed") : "disabled"} (autoAllow: ${c.bwrap.autoAllow}, network: ${c.bwrap.network}, fallback: ${c.bwrap.fallback})`,
				].join("\n"),
				"info",
			);
		},
	});
}
