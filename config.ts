import * as fs from "node:fs";
import * as path from "node:path";
import { applyEdits, modify, parse as parseJsonc, printParseErrorCode, type ParseError } from "jsonc-parser";
import picomatch from "picomatch";
import { commandGlobToRegex } from "./commands";
import { escapeGlob, expandTilde, extensionDir, homeDir, Mutex } from "./util";

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
	/** Paths inside the writable cwd that are re-bound read-only (relative to cwd). Missing paths skipped. */
	readOnly: string[];
	/** Host socket paths re-bound into the sandbox after the socket tmpfs masks. Global-only. */
	allowSockets: string[];
	/** Mask files/dirs in the cwd that match `paths.deny` so subprocesses cannot read them either. */
	maskProjectDenies: boolean;
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
	/** Allow the agent to edit this extension's own directory (global-only; for developing the extension). */
	selfEdit: boolean;
	/** Let a project config loosen the policy (global-only escape hatch). */
	allowProjectLoosening: boolean;
	/** Write a JSONL audit log of every decision (global-only). */
	audit: boolean;
}

/** Config file shape: lists present when parsed, scalars optional for layering. */
export interface PartialConfig {
	mode?: "enforce" | "off";
	tools?: { allow: string[]; deny: string[]; default?: "allow" | "ask" };
	commands?: { allow: string[]; deny: string[]; proxies?: string[] };
	paths?: PatternList;
	bwrap?: Partial<BwrapConfig>;
	selfEdit?: boolean;
	allowProjectLoosening?: boolean;
	audit?: boolean;
}

/**
 * Hard denies: always appended to the effective command deny list and
 * never overridable by user config. These launder or amplify the allowlist
 * (eval, nested shells) or are unrecoverable (mkfs, dd to devices, sudo).
 * Matched against every canonical form of a command (see commands.ts).
 */
export const HARD_COMMAND_DENIES: string[] = [
	"eval *",
	"bash -c *",
	"sh -c *",
	"zsh -c *",
	"dash -c *",
	"ksh -c *",
	"fish -c *",
	"busybox sh *",
	"sudo *",
	"doas *",
	"su *",
	"pkexec *",
	"run0 *",
	"rm -rf /",
	"rm -rf /*",
	"rm -rf ~*",
	"rm -rf ~/*",
	"mkfs*",
	"dd *of=/dev/*",
	"chmod -R * /",
	"chown -R * /",
	"* > /dev/sd*",
	"* > /dev/nvme*",
];

/**
 * Commands that can run arbitrary code from their arguments. They always
 * ask: never allow-matched by a pattern, never downgraded by autoAllow and
 * never persisted as a prefix.
 */
export const NEVER_AUTO_COMMANDS: string[] = [
	"python* -c *",
	"python* -m *",
	"node -e *",
	"node --eval *",
	"node -p *",
	"perl -e *",
	"perl -E *",
	"ruby -e *",
	"bun -e *",
	"bun --eval *",
	"deno eval *",
	"xargs *",
	"find * -exec*",
	"find * -execdir*",
	"find * -ok*",
	"find * -delete*",
	"git -c *",
];

export const DEFAULT_CONFIG: SandboxConfig = {
	mode: "enforce",
	tools: { allow: [], deny: [], default: "ask" },
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
		denyRead: [
			"~/.ssh",
			"~/.aws",
			"~/.gnupg",
			"~/.kube",
			"~/.docker/config.json",
			"~/.pi/agent/auth.json",
			"~/.config/gh",
			"~/.git-credentials",
			"~/.netrc",
			"~/.npmrc",
			"~/.pypirc",
			"~/.cargo/credentials",
			"~/.cargo/credentials.toml",
			"~/.config/gcloud",
			"~/.azure",
			"~/.password-store",
			"~/.local/share/keyrings",
			"~/.mozilla",
			"~/.config/google-chrome",
			"~/.config/chromium",
			"~/.config/BraveSoftware",
			"~/.terraform.d/credentials.tfrc.json",
		],
		readOnly: [".git/hooks", ".git/config", ".git/info", ".pi", ".envrc", ".vscode", ".idea", ".husky"],
		allowSockets: [],
		maskProjectDenies: true,
		maskEnv: [
			"AWS_*",
			"GITHUB_TOKEN",
			"*_API_KEY",
			"*_SECRET*",
			"*TOKEN*",
			"*PASSWORD*",
			"*PASSWD*",
			"*_KEY",
			"*CREDENTIAL*",
			"ANTHROPIC_*",
			"OPENAI_*",
		],
		fallback: "ask",
		userBash: false,
	},
	selfEdit: false,
	allowProjectLoosening: false,
	audit: false,
};

export function globalConfigPath(): string {
	return path.join(homeDir(), ".pi", "agent", "sandbox.json");
}

export function projectConfigPath(cwd: string): string {
	return path.join(cwd, ".pi", "sandbox.json");
}

/** Raw devices: writing to them destroys data, so writes (redirects, write/edit tools) are always denied. */
export const RAW_DEVICE_PATTERNS: string[] = [
	"/dev/sd*",
	"/dev/hd*",
	"/dev/vd*",
	"/dev/xvd*",
	"/dev/nvme*",
	"/dev/mmcblk*",
	"/dev/loop*",
	"/dev/dm-*",
	"/dev/md*",
	"/dev/mapper/**",
	"/dev/disk/**",
];

/**
 * Absolute path patterns the agent may never WRITE to (hard deny, before user
 * lists, not overridable by project config): the sandbox policy files, the
 * extension's own code and git hooks/config.
 */
export function computeProtectedWritePaths(cwd: string, selfEdit: boolean): string[] {
	const patterns: string[] = [];
	for (const file of [globalConfigPath(), projectConfigPath(cwd)]) {
		const base = escapeGlob(file);
		patterns.push(base, `${base}.bak`, `${base}.tmp`);
	}
	if (!selfEdit) patterns.push(`${escapeGlob(extensionDir())}/**`);
	patterns.push(`${escapeGlob(path.join(cwd, ".git", "hooks"))}/**`, escapeGlob(path.join(cwd, ".git", "config")));
	patterns.push(...RAW_DEVICE_PATTERNS);
	return patterns;
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

export interface ConfigError {
	file: string;
	message: string;
	line: number;
	column: number;
}

export interface ParseResult {
	config?: PartialConfig;
	warnings: string[];
	error?: ConfigError;
}

function isStringArray(value: unknown): value is string[] {
	return Array.isArray(value) && value.every((v) => typeof v === "string");
}

/**
 * Strip // and /* *\/ comments from JSONC text. String-aware: comment
 * markers inside string literals (e.g. "dd *of=/dev/*") are preserved.
 * (Config parsing itself uses jsonc-parser; this helper is kept as a
 * dependency-free, tested utility.)
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

function lineColumn(text: string, offset: number): { line: number; column: number } {
	let line = 1;
	let column = 1;
	for (let i = 0; i < offset && i < text.length; i++) {
		if (text[i] === "\n") {
			line++;
			column = 1;
		} else column++;
	}
	return { line, column };
}

const TOP_KEYS = new Set(["mode", "tools", "commands", "paths", "bwrap", "selfEdit", "allowProjectLoosening", "audit"]);
const TOOLS_KEYS = new Set(["allow", "deny", "default"]);
const COMMANDS_KEYS = new Set(["allow", "deny", "proxies"]);
const PATHS_KEYS = new Set(["allow", "deny"]);
const BWRAP_KEYS = new Set([
	"enabled",
	"autoAllow",
	"network",
	"allowWrite",
	"denyRead",
	"readOnly",
	"allowSockets",
	"maskProjectDenies",
	"maskEnv",
	"fallback",
	"userBash",
]);

function checkKeys(where: string, record: Record<string, unknown>, known: Set<string>, warnings: string[]): void {
	for (const key of Object.keys(record)) {
		if (key.startsWith("$") || key.startsWith("_")) continue;
		if (!known.has(key)) warnings.push(`unknown key "${where}${key}" (ignored)`);
	}
}

function listField(
	where: string,
	record: Record<string, unknown>,
	key: string,
	warnings: string[],
	validate?: (pattern: string) => boolean,
): string[] {
	const value = record[key];
	if (value === undefined) return [];
	if (!isStringArray(value)) {
		warnings.push(`"${where}${key}" must be an array of strings (ignored)`);
		return [];
	}
	if (!validate) return value;
	const ok: string[] = [];
	for (const pattern of value) {
		if (validate(pattern)) ok.push(pattern);
		else warnings.push(`"${where}${key}": pattern "${pattern}" does not compile (ignored)`);
	}
	return ok;
}

function compilesAsPath(pattern: string): boolean {
	try {
		picomatch(pattern, { dot: true });
		return true;
	} catch {
		return false;
	}
}

function compilesAsCommand(pattern: string): boolean {
	try {
		commandGlobToRegex(pattern);
		return true;
	} catch {
		return false;
	}
}

function asRecord(where: string, value: unknown, warnings: string[]): Record<string, unknown> | undefined {
	if (value === undefined) return undefined;
	if (typeof value !== "object" || value === null || Array.isArray(value)) {
		warnings.push(`"${where}" must be an object (ignored)`);
		return undefined;
	}
	return value as Record<string, unknown>;
}

function boolField(where: string, record: Record<string, unknown>, key: string, warnings: string[]): boolean | undefined {
	const value = record[key];
	if (value === undefined) return undefined;
	if (typeof value !== "boolean") {
		warnings.push(`"${where}${key}" must be true or false (ignored)`);
		return undefined;
	}
	return value;
}

function enumField<T extends string>(
	where: string,
	record: Record<string, unknown>,
	key: string,
	allowed: readonly T[],
	warnings: string[],
): T | undefined {
	const value = record[key];
	if (value === undefined) return undefined;
	if (typeof value === "string" && (allowed as readonly string[]).includes(value)) return value as T;
	warnings.push(`"${where}${key}" must be one of ${allowed.map((a) => `"${a}"`).join(", ")} (ignored)`);
	return undefined;
}

/** Validate a parsed config object into a PartialConfig, collecting warnings. */
export function validateConfig(parsed: unknown): { config: PartialConfig; warnings: string[] } {
	const warnings: string[] = [];
	const config: PartialConfig = {};
	const record = asRecord("(root)", parsed, warnings);
	if (!record) return { config, warnings };
	checkKeys("", record, TOP_KEYS, warnings);

	const mode = enumField("", record, "mode", ["enforce", "off"], warnings);
	if (mode) config.mode = mode;

	const tools = asRecord("tools", record.tools, warnings);
	config.tools = { allow: [], deny: [] };
	if (tools) {
		checkKeys("tools.", tools, TOOLS_KEYS, warnings);
		config.tools.allow = listField("tools.", tools, "allow", warnings, compilesAsCommand);
		config.tools.deny = listField("tools.", tools, "deny", warnings, compilesAsCommand);
		const d = enumField("tools.", tools, "default", ["allow", "ask"], warnings);
		if (d) config.tools.default = d;
	}

	const commands = asRecord("commands", record.commands, warnings);
	config.commands = { allow: [], deny: [] };
	if (commands) {
		checkKeys("commands.", commands, COMMANDS_KEYS, warnings);
		config.commands.allow = listField("commands.", commands, "allow", warnings, compilesAsCommand);
		config.commands.deny = listField("commands.", commands, "deny", warnings, compilesAsCommand);
		if (commands.proxies !== undefined) {
			if (isStringArray(commands.proxies)) config.commands.proxies = commands.proxies;
			else warnings.push(`"commands.proxies" must be an array of strings (ignored)`);
		}
	}

	const paths = asRecord("paths", record.paths, warnings);
	config.paths = { allow: [], deny: [] };
	if (paths) {
		checkKeys("paths.", paths, PATHS_KEYS, warnings);
		config.paths.allow = listField("paths.", paths, "allow", warnings, compilesAsPath);
		config.paths.deny = listField("paths.", paths, "deny", warnings, compilesAsPath);
	}

	const b = asRecord("bwrap", record.bwrap, warnings);
	if (b) {
		checkKeys("bwrap.", b, BWRAP_KEYS, warnings);
		const bwrap: Partial<BwrapConfig> = {};
		const enabled = boolField("bwrap.", b, "enabled", warnings);
		if (enabled !== undefined) bwrap.enabled = enabled;
		const autoAllow = boolField("bwrap.", b, "autoAllow", warnings);
		if (autoAllow !== undefined) bwrap.autoAllow = autoAllow;
		const network = enumField("bwrap.", b, "network", ["allow", "off"], warnings);
		if (network) bwrap.network = network;
		if (b.allowWrite !== undefined) bwrap.allowWrite = listField("bwrap.", b, "allowWrite", warnings);
		if (b.denyRead !== undefined) bwrap.denyRead = listField("bwrap.", b, "denyRead", warnings);
		if (b.readOnly !== undefined) bwrap.readOnly = listField("bwrap.", b, "readOnly", warnings);
		if (b.allowSockets !== undefined) bwrap.allowSockets = listField("bwrap.", b, "allowSockets", warnings);
		if (b.maskEnv !== undefined) bwrap.maskEnv = listField("bwrap.", b, "maskEnv", warnings, compilesAsCommand);
		const mask = boolField("bwrap.", b, "maskProjectDenies", warnings);
		if (mask !== undefined) bwrap.maskProjectDenies = mask;
		const fallback = enumField("bwrap.", b, "fallback", ["ask", "block"], warnings);
		if (fallback) bwrap.fallback = fallback;
		const userBash = boolField("bwrap.", b, "userBash", warnings);
		if (userBash !== undefined) bwrap.userBash = userBash;
		config.bwrap = bwrap;
	}

	for (const key of ["selfEdit", "allowProjectLoosening", "audit"] as const) {
		const v = boolField("", record, key, warnings);
		if (v !== undefined) config[key] = v;
	}
	return { config, warnings };
}

/**
 * Parse a config file (JSONC: comments and trailing commas tolerated).
 * A missing file yields `{ config: undefined, warnings: [] }` with no error;
 * a malformed one yields an `error` with line/column.
 */
export function parseConfigFile(filePath: string): ParseResult {
	let raw: string;
	try {
		raw = fs.readFileSync(filePath, "utf8");
	} catch (err) {
		if ((err as NodeJS.ErrnoException).code === "ENOENT") return { warnings: [] };
		return {
			warnings: [],
			error: { file: filePath, message: `cannot read: ${(err as Error).message}`, line: 0, column: 0 },
		};
	}
	const errors: ParseError[] = [];
	const parsed: unknown = parseJsonc(raw, errors, { allowTrailingComma: true, disallowComments: false });
	if (errors.length > 0) {
		const first = errors[0];
		return {
			warnings: [],
			error: {
				file: filePath,
				message: printParseErrorCode(first.error),
				...lineColumn(raw, first.offset),
			},
		};
	}
	if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
		return {
			warnings: [],
			error: { file: filePath, message: "top level must be a JSON object", line: 1, column: 1 },
		};
	}
	const { config, warnings } = validateConfig(parsed);
	return { config, warnings: warnings.map((w) => `${filePath}: ${w}`) };
}

// ---------------------------------------------------------------------------
// Merging
// ---------------------------------------------------------------------------

export interface MergeOptions {
	/** Project directory: project `bwrap.allowWrite` entries outside it are ignored. */
	cwd?: string;
}

function insideDir(candidate: string, dir: string): boolean {
	const rel = path.relative(dir, candidate);
	return rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel));
}

/**
 * Merge global and project config over the built-in defaults.
 * Lists concatenate (defaults < global < project); denies always win at
 * evaluation time. A project config may only TIGHTEN the policy: loosening
 * settings are ignored (with a warning) unless the global config sets
 * `allowProjectLoosening: true`.
 */
export function mergeConfigsDetailed(
	globalConfig: PartialConfig | undefined,
	projectConfig: PartialConfig | undefined,
	options: MergeOptions = {},
): { config: SandboxConfig; warnings: string[] } {
	const warnings: string[] = [];
	const D = DEFAULT_CONFIG;
	const loosenOk = globalConfig?.allowProjectLoosening === true;

	// Value before the project layer is applied.
	const baseMode = globalConfig?.mode ?? D.mode;
	const baseToolsDefault = globalConfig?.tools?.default ?? D.tools.default;
	const baseEnabled = globalConfig?.bwrap?.enabled ?? D.bwrap.enabled;
	const baseAutoAllow = globalConfig?.bwrap?.autoAllow ?? D.bwrap.autoAllow;
	const baseNetwork = globalConfig?.bwrap?.network ?? D.bwrap.network;
	const baseFallback = globalConfig?.bwrap?.fallback ?? D.bwrap.fallback;
	const baseMask = globalConfig?.bwrap?.maskProjectDenies ?? D.bwrap.maskProjectDenies;

	/** Take the project's value unless it loosens the base value. */
	function tighten<T>(name: string, base: T, projectValue: T | undefined, isLooser: (p: T, b: T) => boolean): T {
		if (projectValue === undefined) return base;
		if (!loosenOk && isLooser(projectValue, base)) {
			warnings.push(
				`project config: ignored "${name}: ${JSON.stringify(projectValue)}" (a project may only tighten the policy; set "allowProjectLoosening": true globally to allow it)`,
			);
			return base;
		}
		return projectValue;
	}

	const p = projectConfig;
	const mode = tighten("mode", baseMode, p?.mode, (x, b) => x === "off" && b !== "off");
	const toolsDefault = tighten("tools.default", baseToolsDefault, p?.tools?.default, (x, b) => x === "allow" && b === "ask");
	const enabled = tighten("bwrap.enabled", baseEnabled, p?.bwrap?.enabled, (x, b) => x === false && b === true);
	const autoAllow = tighten("bwrap.autoAllow", baseAutoAllow, p?.bwrap?.autoAllow, (x, b) => x === true && b === false);
	const network = tighten("bwrap.network", baseNetwork, p?.bwrap?.network, (x, b) => x === "allow" && b === "off");
	const fallback = tighten("bwrap.fallback", baseFallback, p?.bwrap?.fallback, (x, b) => x === "ask" && b === "block");
	const maskProjectDenies = tighten(
		"bwrap.maskProjectDenies",
		baseMask,
		p?.bwrap?.maskProjectDenies,
		(x, b) => x === false && b === true,
	);

	let projectAllowWrite = p?.bwrap?.allowWrite ?? [];
	if (!loosenOk && options.cwd !== undefined) {
		const cwd = options.cwd;
		projectAllowWrite = projectAllowWrite.filter((entry) => {
			const abs = path.resolve(cwd, expandTilde(entry));
			if (insideDir(abs, cwd)) return true;
			warnings.push(`project config: ignored bwrap.allowWrite "${entry}" (outside the project)`);
			return false;
		});
	} else if (!loosenOk && options.cwd === undefined && projectAllowWrite.length > 0) {
		warnings.push("project config: bwrap.allowWrite ignored (project directory unknown)");
		projectAllowWrite = [];
	}
	let projectAllowSockets = p?.bwrap?.allowSockets ?? [];
	if (!loosenOk && projectAllowSockets.length > 0) {
		warnings.push("project config: ignored bwrap.allowSockets (global-only setting)");
		projectAllowSockets = [];
	}
	if (!loosenOk && p?.selfEdit !== undefined) warnings.push("project config: ignored selfEdit (global-only setting)");
	if (p?.allowProjectLoosening !== undefined) warnings.push("project config: ignored allowProjectLoosening (global-only setting)");
	if (p?.audit !== undefined) warnings.push("project config: ignored audit (global-only setting)");

	const config: SandboxConfig = {
		mode,
		tools: {
			allow: [...D.tools.allow, ...(globalConfig?.tools?.allow ?? []), ...(p?.tools?.allow ?? [])],
			deny: [...D.tools.deny, ...(globalConfig?.tools?.deny ?? []), ...(p?.tools?.deny ?? [])],
			default: toolsDefault,
		},
		commands: {
			allow: [...D.commands.allow, ...(globalConfig?.commands?.allow ?? []), ...(p?.commands?.allow ?? [])],
			deny: [
				...D.commands.deny,
				...(globalConfig?.commands?.deny ?? []),
				...(p?.commands?.deny ?? []),
				...HARD_COMMAND_DENIES,
			],
			// Override (not concat) so [] disables unwrapping. A project cannot add proxies
			// (proxy unwrapping widens what an allow pattern matches).
			proxies: globalConfig?.commands?.proxies ?? D.commands.proxies,
		},
		bwrap: {
			enabled,
			autoAllow,
			network,
			allowWrite: [...D.bwrap.allowWrite, ...(globalConfig?.bwrap?.allowWrite ?? []), ...projectAllowWrite],
			denyRead: [...D.bwrap.denyRead, ...(globalConfig?.bwrap?.denyRead ?? []), ...(p?.bwrap?.denyRead ?? [])],
			readOnly: [...D.bwrap.readOnly, ...(globalConfig?.bwrap?.readOnly ?? []), ...(p?.bwrap?.readOnly ?? [])],
			allowSockets: [...D.bwrap.allowSockets, ...(globalConfig?.bwrap?.allowSockets ?? []), ...projectAllowSockets],
			maskProjectDenies,
			maskEnv: [...D.bwrap.maskEnv, ...(globalConfig?.bwrap?.maskEnv ?? []), ...(p?.bwrap?.maskEnv ?? [])],
			fallback,
			userBash: p?.bwrap?.userBash ?? globalConfig?.bwrap?.userBash ?? D.bwrap.userBash,
		},
		paths: {
			allow: [...D.paths.allow, ...(globalConfig?.paths?.allow ?? []), ...(p?.paths?.allow ?? [])],
			deny: [...D.paths.deny, ...(globalConfig?.paths?.deny ?? []), ...(p?.paths?.deny ?? [])],
		},
		selfEdit: globalConfig?.selfEdit ?? D.selfEdit,
		allowProjectLoosening: globalConfig?.allowProjectLoosening ?? D.allowProjectLoosening,
		audit: globalConfig?.audit ?? D.audit,
	};
	return { config, warnings };
}

export function mergeConfigs(
	globalConfig: PartialConfig | undefined,
	projectConfig: PartialConfig | undefined,
	options: MergeOptions = {},
): SandboxConfig {
	return mergeConfigsDetailed(globalConfig, projectConfig, options).config;
}

/** Strict overrides applied when a config file is malformed: never looser than the defaults. */
export function applyStrict(config: SandboxConfig): SandboxConfig {
	return {
		...config,
		mode: "enforce",
		tools: { ...config.tools, default: "ask" },
		bwrap: { ...config.bwrap, autoAllow: false, fallback: "block" },
	};
}

export interface LoadedConfig {
	effective: SandboxConfig;
	globalFile: string;
	projectFile: string;
	globalMalformed: boolean;
	projectMalformed: boolean;
	/** Parse errors (with line/column). Non-empty means the config is in strict fail-closed mode. */
	errors: ConfigError[];
	/** Validation warnings and ignored project settings. */
	warnings: string[];
	/** True when a config file failed to parse and strict defaults are in force. */
	configError: boolean;
	/** Whether the global file sets `tools.default` explicitly (drives the first-run notice). */
	globalSetsToolsDefault: boolean;
	/** The project layer as parsed (for tagging project entries in /sandbox list). */
	projectLayer?: PartialConfig;
	/** Absolute path patterns the agent may never write to. */
	protectedWrite: string[];
	/**
	 * Per-layer path deny arrays, used by the radius disclosure renderer
	 * for deterministic capping (built-ins always, then global, then project).
	 */
	denyLayers: {
		builtin: string[];
		global: string[];
		project: string[];
	};
}

/**
 * Load and merge config. Project config is only honored when the project is
 * trusted. A malformed file puts the sandbox in strict fail-closed mode
 * (never silently dropping the user's denies).
 */
export function loadConfig(cwd: string, projectTrusted: boolean): LoadedConfig {
	const globalFile = globalConfigPath();
	const projectFile = projectConfigPath(cwd);

	const globalResult = parseConfigFile(globalFile);
	const projectResult = projectTrusted ? parseConfigFile(projectFile) : { warnings: [] as string[] };

	const errors: ConfigError[] = [];
	if (globalResult.error) errors.push(globalResult.error);
	if (projectResult.error) errors.push(projectResult.error);

	const merged = mergeConfigsDetailed(globalResult.config, projectResult.config, { cwd });
	const configError = errors.length > 0;
	const effective = configError ? applyStrict(merged.config) : merged.config;

	return {
		effective,
		globalFile,
		projectFile,
		globalMalformed: globalResult.error !== undefined,
		projectMalformed: projectResult.error !== undefined,
		errors,
		warnings: [...globalResult.warnings, ...projectResult.warnings, ...merged.warnings],
		configError,
		globalSetsToolsDefault: globalResult.config?.tools?.default !== undefined,
		projectLayer: projectResult.config,
		protectedWrite: computeProtectedWritePaths(cwd, effective.selfEdit),
		denyLayers: {
			builtin: [...DEFAULT_CONFIG.paths.deny],
			global: globalResult.config?.paths?.deny ?? [],
			project: projectResult.config?.paths?.deny ?? [],
		},
	};
}

// ---------------------------------------------------------------------------
// Saving
// ---------------------------------------------------------------------------

export class ConfigWriteError extends Error {}

export type ConfigUpdate =
	| { kind: "command" | "path" | "tool"; pattern: string }
	| { kind: "mode"; mode: "enforce" | "off" };

const writeMutex = new Mutex();
const FORMAT = { insertSpaces: true, tabSize: 2, eol: "\n" };

/**
 * Persist a single allow pattern (or the mode) to a config file: the project
 * file when trusted (allow patterns only), otherwise the global one. Edits are
 * applied in place with jsonc-parser so comments and formatting survive; the
 * write is atomic (tmp + fsync + rename) and keeps one `.bak`. A file that does
 * not currently parse is never overwritten. Writes are serialized in-process.
 * Returns the file written.
 */
export function saveToConfig(
	cwd: string,
	projectTrusted: boolean,
	update: ConfigUpdate,
	target?: "global" | "project",
): Promise<string> {
	const useProject = target ? target === "project" : projectTrusted && update.kind !== "mode";
	const filePath = useProject ? projectConfigPath(cwd) : globalConfigPath();
	return writeMutex.run(async () => writeConfigUpdate(filePath, update));
}

export function writeConfigUpdate(filePath: string, update: ConfigUpdate): string {
	let text = "{}\n";
	let existed = false;
	try {
		text = fs.readFileSync(filePath, "utf8");
		existed = true;
	} catch (err) {
		if ((err as NodeJS.ErrnoException).code !== "ENOENT") {
			throw new ConfigWriteError(`cannot read ${filePath}: ${(err as Error).message}`);
		}
	}
	if (text.trim().length === 0) text = "{}\n";

	const errors: ParseError[] = [];
	const current: unknown = parseJsonc(text, errors, { allowTrailingComma: true });
	if (errors.length > 0 || typeof current !== "object" || current === null || Array.isArray(current)) {
		const where = errors[0] ? lineColumn(text, errors[0].offset) : { line: 1, column: 1 };
		throw new ConfigWriteError(
			`${filePath} does not parse (line ${where.line}, column ${where.column}); fix it by hand — the sandbox will not overwrite it`,
		);
	}
	const record = current as Record<string, unknown>;

	let next = text;
	if (update.kind === "mode") {
		next = applyEdits(text, modify(text, ["mode"], update.mode, { formattingOptions: FORMAT }));
	} else {
		const section = update.kind === "command" ? "commands" : update.kind === "path" ? "paths" : "tools";
		const sectionValue = record[section];
		const allow =
			typeof sectionValue === "object" && sectionValue !== null && isStringArray((sectionValue as Record<string, unknown>).allow)
				? ((sectionValue as Record<string, unknown>).allow as string[])
				: undefined;
		if (allow?.includes(update.pattern)) return filePath;
		const edits = allow
			? modify(text, [section, "allow", -1], update.pattern, { formattingOptions: FORMAT, isArrayInsertion: true })
			: modify(text, [section, "allow"], [update.pattern], { formattingOptions: FORMAT });
		next = applyEdits(text, edits);
	}
	if (!next.endsWith("\n")) next += "\n";

	fs.mkdirSync(path.dirname(filePath), { recursive: true });
	if (existed) {
		try {
			fs.copyFileSync(filePath, `${filePath}.bak`);
		} catch {
			// best effort
		}
	}
	const tmp = `${filePath}.tmp`;
	const fd = fs.openSync(tmp, "w", 0o600);
	try {
		fs.writeSync(fd, next);
		fs.fsyncSync(fd);
	} finally {
		fs.closeSync(fd);
	}
	fs.renameSync(tmp, filePath);
	return filePath;
}
