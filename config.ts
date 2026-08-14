import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

export interface PatternList {
	allow: string[];
	deny: string[];
}

export interface ToolsPolicy extends PatternList {
	/** Verdict for custom tools in neither list. Built-ins always continue to command/path checks. */
	default: "allow" | "ask";
}

export interface CommandPolicyConfig extends PatternList {
	/** Proxy binaries (e.g. rtk) unwrapped before command matching. */
	proxies: string[];
}

export interface BwrapConfig {
	/** Master switch: wrap bash commands in bubblewrap. */
	enabled: boolean;
	/** Bash-derived asks become allows when bwrap is confirmed working. Denies never downgrade. */
	autoAllow: boolean;
	/** "allow" = unchanged network; "off" = --unshare-net. */
	network: "allow" | "off";
	/** Extra writable paths inside the sandbox (build caches etc.). Missing paths skipped. */
	allowWrite: string[];
	/** Paths hidden from the sandbox (tmpfs over dirs, /dev/null over files). Missing paths skipped. */
	denyRead: string[];
	/** Globs matched against env var names; matches are unset inside the sandbox. */
	maskEnv: string[];
	/** Behavior when bwrap is missing or fails to launch: "ask" = degrade to guardrail, "block" = fail bash. */
	fallback: "ask" | "block";
	/** Also sandbox the user's own ! / !! commands. */
	userBash: boolean;
}

export interface SandboxConfig {
	mode: "enforce" | "off";
	tools: ToolsPolicy;
	commands: CommandPolicyConfig;
	paths: PatternList;
	bwrap: BwrapConfig;
}

/** Config file shape: lists present when parsed, scalars optional for layering. */
export interface PartialConfig {
	mode?: "enforce" | "off";
	tools?: { allow: string[]; deny: string[]; default?: "allow" | "ask" };
	commands?: { allow: string[]; deny: string[]; proxies?: string[] };
	paths?: PatternList;
	bwrap?: Partial<BwrapConfig>;
}

/**
 * Hard denies: always appended to the effective command deny list and
 * never overridable by user config. These launder or amplify the allowlist
 * (eval, nested shells) or are unrecoverable (mkfs, dd to devices, sudo).
 */
export const HARD_COMMAND_DENIES: string[] = [
	"eval *",
	"bash -c *",
	"sh -c *",
	"sudo *",
	"rm -rf /",
	"rm -rf ~*",
	"mkfs*",
	"dd *of=/dev/*",
];

export const DEFAULT_CONFIG: SandboxConfig = {
	mode: "enforce",
	tools: { allow: [], deny: [], default: "allow" },
	commands: {
		allow: [],
		deny: [],
		proxies: ["rtk"],
	},
	paths: {
		allow: ["./**"],
		deny: ["**/.env", "**/.env.*", "**/.git/**", "**/.ssh/**", "**/id_rsa*", "**/*.pem"],
	},
	bwrap: {
		enabled: true,
		autoAllow: false,
		network: "allow",
		allowWrite: ["~/.gradle", "~/.m2", "~/.npm", "~/.cache"],
		denyRead: ["~/.ssh", "~/.aws", "~/.gnupg", "~/.kube", "~/.docker/config.json"],
		maskEnv: ["AWS_*", "GITHUB_TOKEN", "*_API_KEY", "*_SECRET*"],
		fallback: "ask",
		userBash: false,
	},
};

export function globalConfigPath(): string {
	return path.join(os.homedir(), ".pi", "agent", "sandbox.json");
}

export function projectConfigPath(cwd: string): string {
	return path.join(cwd, ".pi", "sandbox.json");
}

function isStringArray(value: unknown): value is string[] {
	return Array.isArray(value) && value.every((v) => typeof v === "string");
}

function parsePatternList(value: unknown): PatternList {
	const list: PatternList = { allow: [], deny: [] };
	if (typeof value !== "object" || value === null) return list;
	const record = value as Record<string, unknown>;
	if (isStringArray(record.allow)) list.allow = record.allow;
	if (isStringArray(record.deny)) list.deny = record.deny;
	return list;
}

/**
 * Strip // and /* *\/ comments from JSONC text. String-aware: comment
 * markers inside string literals (e.g. "dd *of=/dev/*") are preserved.
 */
export function stripJsonComments(text: string): string {
	let out = "";
	let inString = false;
	let i = 0;
	while (i < text.length) {
		const ch = text[i];
		const next = text[i + 1];
		if (inString) {
			out += ch;
			if (ch === "\\") {
				out += next ?? "";
				i += 2;
				continue;
			}
			if (ch === '"') inString = false;
			i++;
			continue;
		}
		if (ch === '"') {
			inString = true;
			out += ch;
			i++;
			continue;
		}
		if (ch === "/" && next === "/") {
			while (i < text.length && text[i] !== "\n") i++;
			continue;
		}
		if (ch === "/" && next === "*") {
			i += 2;
			while (i < text.length && !(text[i] === "*" && text[i + 1] === "/")) i++;
			i += 2;
			continue;
		}
		out += ch;
		i++;
	}
	return out;
}

/** Parse a config file. Tolerates JSONC comments. Returns undefined for missing or malformed files. */
export function parseConfigFile(filePath: string): PartialConfig | undefined {
	let raw: string;
	try {
		raw = fs.readFileSync(filePath, "utf8");
	} catch {
		return undefined;
	}
	let parsed: unknown;
	try {
		parsed = JSON.parse(stripJsonComments(raw));
	} catch {
		return undefined;
	}
	if (typeof parsed !== "object" || parsed === null) return undefined;
	const record = parsed as Record<string, unknown>;
	const config: PartialConfig = {};
	if (record.mode === "enforce" || record.mode === "off") config.mode = record.mode;

	const tools = parsePatternList(record.tools);
	const toolsDefault =
		typeof record.tools === "object" && record.tools !== null
			? (record.tools as Record<string, unknown>).default
			: undefined;
	config.tools = {
		...tools,
		...(toolsDefault === "allow" || toolsDefault === "ask" ? { default: toolsDefault } : {}),
	};

	const commands = parsePatternList(record.commands);
	const proxies =
		typeof record.commands === "object" && record.commands !== null
			? (record.commands as Record<string, unknown>).proxies
			: undefined;
	config.commands = {
		...commands,
		...(isStringArray(proxies) ? { proxies } : {}),
	};

	config.paths = parsePatternList(record.paths);

	if (typeof record.bwrap === "object" && record.bwrap !== null) {
		const b = record.bwrap as Record<string, unknown>;
		const bwrap: Partial<BwrapConfig> = {};
		if (typeof b.enabled === "boolean") bwrap.enabled = b.enabled;
		if (typeof b.autoAllow === "boolean") bwrap.autoAllow = b.autoAllow;
		if (b.network === "allow" || b.network === "off") bwrap.network = b.network;
		if (isStringArray(b.allowWrite)) bwrap.allowWrite = b.allowWrite;
		if (isStringArray(b.denyRead)) bwrap.denyRead = b.denyRead;
		if (isStringArray(b.maskEnv)) bwrap.maskEnv = b.maskEnv;
		if (b.fallback === "ask" || b.fallback === "block") bwrap.fallback = b.fallback;
		if (typeof b.userBash === "boolean") bwrap.userBash = b.userBash;
		config.bwrap = bwrap;
	}
	return config;
}

/**
 * Merge global and project config over the built-in defaults.
 * Lists concatenate (defaults < global < project); denies always win at
 * evaluation time. Project mode wins over global mode when set.
 */
export function mergeConfigs(
	globalConfig: PartialConfig | undefined,
	projectConfig: PartialConfig | undefined,
): SandboxConfig {
	return {
		mode: projectConfig?.mode ?? globalConfig?.mode ?? DEFAULT_CONFIG.mode,
		tools: {
			allow: [
				...DEFAULT_CONFIG.tools.allow,
				...(globalConfig?.tools?.allow ?? []),
				...(projectConfig?.tools?.allow ?? []),
			],
			deny: [
				...DEFAULT_CONFIG.tools.deny,
				...(globalConfig?.tools?.deny ?? []),
				...(projectConfig?.tools?.deny ?? []),
			],
			default: projectConfig?.tools?.default ?? globalConfig?.tools?.default ?? DEFAULT_CONFIG.tools.default,
		},
		commands: {
			allow: [
				...DEFAULT_CONFIG.commands.allow,
				...(globalConfig?.commands?.allow ?? []),
				...(projectConfig?.commands?.allow ?? []),
			],
			deny: [
				...DEFAULT_CONFIG.commands.deny,
				...(globalConfig?.commands?.deny ?? []),
				...(projectConfig?.commands?.deny ?? []),
				...HARD_COMMAND_DENIES,
			],
			// Override (not concat) so [] disables unwrapping.
			proxies:
				projectConfig?.commands?.proxies ?? globalConfig?.commands?.proxies ?? DEFAULT_CONFIG.commands.proxies,
		},
		bwrap: {
			enabled: projectConfig?.bwrap?.enabled ?? globalConfig?.bwrap?.enabled ?? DEFAULT_CONFIG.bwrap.enabled,
			autoAllow:
				projectConfig?.bwrap?.autoAllow ?? globalConfig?.bwrap?.autoAllow ?? DEFAULT_CONFIG.bwrap.autoAllow,
			network: projectConfig?.bwrap?.network ?? globalConfig?.bwrap?.network ?? DEFAULT_CONFIG.bwrap.network,
			allowWrite: [
				...DEFAULT_CONFIG.bwrap.allowWrite,
				...(globalConfig?.bwrap?.allowWrite ?? []),
				...(projectConfig?.bwrap?.allowWrite ?? []),
			],
			denyRead: [
				...DEFAULT_CONFIG.bwrap.denyRead,
				...(globalConfig?.bwrap?.denyRead ?? []),
				...(projectConfig?.bwrap?.denyRead ?? []),
			],
			maskEnv: [
				...DEFAULT_CONFIG.bwrap.maskEnv,
				...(globalConfig?.bwrap?.maskEnv ?? []),
				...(projectConfig?.bwrap?.maskEnv ?? []),
			],
			fallback:
				projectConfig?.bwrap?.fallback ?? globalConfig?.bwrap?.fallback ?? DEFAULT_CONFIG.bwrap.fallback,
			userBash:
				projectConfig?.bwrap?.userBash ?? globalConfig?.bwrap?.userBash ?? DEFAULT_CONFIG.bwrap.userBash,
		},
		paths: {
			allow: [
				...DEFAULT_CONFIG.paths.allow,
				...(globalConfig?.paths?.allow ?? []),
				...(projectConfig?.paths?.allow ?? []),
			],
			deny: [
				...DEFAULT_CONFIG.paths.deny,
				...(globalConfig?.paths?.deny ?? []),
				...(projectConfig?.paths?.deny ?? []),
			],
		},
	};
}

export interface LoadedConfig {
	effective: SandboxConfig;
	globalFile: string;
	projectFile: string;
	globalMalformed: boolean;
	projectMalformed: boolean;
	/**
	 * Per-layer path deny arrays, used by the radius disclosure renderer
	 * for deterministic capping (built-ins always, then global, then project).
	 * `project` is the per-layer raw config (already merged when project is
	 * untrusted stays an empty array); the renderer does not need this slice
	 * to be authoritative — it only needs to know which patterns came from
	 * which layer so truncation hits project fills last.
	 */
	denyLayers: {
		builtin: string[];
		global: string[];
		project: string[];
	};
}

/**
 * Load and merge config. Project config is only honored when the project is
 * trusted. Malformed files are treated as empty and flagged for notification.
 */
export function loadConfig(cwd: string, projectTrusted: boolean): LoadedConfig {
	const globalFile = globalConfigPath();
	const projectFile = projectConfigPath(cwd);

	const globalExists = fs.existsSync(globalFile);
	const projectExists = projectTrusted && fs.existsSync(projectFile);

	const globalParsed = globalExists ? parseConfigFile(globalFile) : undefined;
	const projectParsed = projectExists ? parseConfigFile(projectFile) : undefined;

	return {
		effective: mergeConfigs(globalParsed, projectParsed),
		globalFile,
		projectFile,
		globalMalformed: globalExists && globalParsed === undefined,
		projectMalformed: projectExists && projectParsed === undefined,
		denyLayers: {
			builtin: [...DEFAULT_CONFIG.paths.deny],
			global: globalParsed?.paths?.deny ?? [],
			project: projectParsed?.paths?.deny ?? [],
		},
	};
}

/**
 * Persist a single allow pattern (or the mode) to the appropriate config file:
 * project config when trusted, global otherwise. Preserves existing keys.
 * Returns the file written.
 */
export function saveToConfig(
	cwd: string,
	projectTrusted: boolean,
	update: { kind: "command" | "path" | "tool"; pattern: string } | { kind: "mode"; mode: "enforce" | "off" },
): string {
	const filePath = projectTrusted ? projectConfigPath(cwd) : globalConfigPath();

	let existing: Record<string, unknown> = {};
	try {
		const parsed: unknown = JSON.parse(stripJsonComments(fs.readFileSync(filePath, "utf8")));
		if (typeof parsed === "object" && parsed !== null) existing = parsed as Record<string, unknown>;
	} catch {
		// Missing or malformed file: start from a skeleton.
	}

	if (update.kind === "mode") {
		existing.mode = update.mode;
	} else {
		const section = update.kind === "command" ? "commands" : update.kind === "path" ? "paths" : "tools";
		const list = parsePatternList(existing[section]);
		if (!list.allow.includes(update.pattern)) list.allow.push(update.pattern);
		// Preserve sibling keys in the section (tools.default, commands.proxies).
		const prev =
			typeof existing[section] === "object" && existing[section] !== null
				? (existing[section] as Record<string, unknown>)
				: {};
		existing[section] = { ...prev, allow: list.allow, deny: list.deny };
	}

	fs.mkdirSync(path.dirname(filePath), { recursive: true });
	fs.writeFileSync(filePath, `${JSON.stringify(existing, null, 2)}\n`, "utf8");
	return filePath;
}
