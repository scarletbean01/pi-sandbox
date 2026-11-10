import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { createRequire } from "node:module";
import { basename } from "./commands";
import type { PathAccess } from "./paths";
import { expandTilde, extensionDir, homeDir } from "./util";

/**
 * Bash analysis on top of tree-sitter-bash (wasm). `analyze()` returns every
 * command (nested ones included), every path-ish word and every reason the
 * command cannot be fully understood. Anything unrecognized is recorded as
 * opaque so a grammar upgrade fails safe.
 */

// Minimal structural types for the parts of web-tree-sitter we use.
interface TSNode {
	type: string;
	text: string;
	isNamed: boolean;
	hasError: boolean;
	isMissing: boolean;
	startIndex: number;
	endIndex: number;
	children: TSNode[];
	namedChildren: TSNode[];
	childForFieldName(name: string): TSNode | null;
	childrenForFieldName(name: string): TSNode[];
}
interface TSParser {
	parse(input: string): { rootNode: TSNode; delete(): void } | null;
}

export interface Word {
	/** Value with quotes removed and escapes resolved. For non-literal words it holds the source text. */
	value: string;
	/** Original source text. */
	text: string;
	/** True when the value is fully known statically. */
	literal: boolean;
	/** Expansions that made the word non-literal (`$X`, `$(…)`, …). */
	expansions: string[];
	/** True when an UNQUOTED glob metacharacter (`* ? [`) is present. */
	glob: boolean;
}

export interface Cmd {
	/** argv words (assignments stripped). */
	argv: Word[];
	/** Leading NAME=value assignments. */
	assignments: { name: string; value: Word }[];
	/** Source text of the command. */
	text: string;
	/** Inside $(), backticks, <(), a subshell or a function body. */
	nested: boolean;
	/** Effective working directory at that point; null = unknown. */
	cwd: string | null;
}

export interface PathRef {
	word: Word;
	access: PathAccess;
	source: "arg" | "redirect" | "cd";
	/** Working directory relative paths resolve against; null = unknown. */
	cwd: string | null;
	/** Index into `commands` of the owning command (undefined for redirects of non-command bodies). */
	cmd?: number;
	/** The word is the value of a `--opt=value` flag. */
	flagValue?: boolean;
}

export interface Analysis {
	commands: Cmd[];
	paths: PathRef[];
	/** Whole-command reasons the analysis is unsure (parse error, unknown syntax, …). */
	opaque: string[];
	parseError: boolean;
	/** False when produced by the crude fallback tokenizer (wasm parser unavailable). */
	parser: boolean;
}

// ---------------------------------------------------------------------------
// Parser loading
// ---------------------------------------------------------------------------

let parser: TSParser | undefined;
let initPromise: Promise<void> | undefined;
let initError: string | undefined;

function findWasm(pkg: string, file: string): string | undefined {
	const candidates: string[] = [path.join(extensionDir(), "node_modules", pkg, file)];
	try {
		const req = createRequire(path.join(extensionDir(), "index.ts"));
		candidates.push(req.resolve(`${pkg}/${file}`));
	} catch {
		// not resolvable
	}
	for (const c of candidates) {
		if (fs.existsSync(c)) return c;
	}
	return undefined;
}

/** Load the wasm parser once. Safe to call repeatedly; never rejects (see parserError()). */
export function initShell(): Promise<void> {
	if (!initPromise) {
		initPromise = (async () => {
			try {
				const core = findWasm("web-tree-sitter", "web-tree-sitter.wasm");
				const bash = findWasm("tree-sitter-bash", "tree-sitter-bash.wasm");
				if (!core || !bash) throw new Error("tree-sitter wasm files not found (run npm install in the extension dir)");
				const ts = (await import("web-tree-sitter")) as unknown as {
					Parser: { init(o: object): Promise<void>; new (): { setLanguage(l: unknown): void } & TSParser };
					Language: { load(p: string): Promise<unknown> };
				};
				await ts.Parser.init({ locateFile: () => core });
				const lang = await ts.Language.load(bash);
				const p = new ts.Parser();
				p.setLanguage(lang);
				// Smoke test: a broken ABI shows up here rather than on the first command.
				const t = p.parse("echo ok");
				if (!t || t.rootNode.hasError) throw new Error("tree-sitter smoke test failed");
				t.delete();
				parser = p;
				initError = undefined;
			} catch (err) {
				parser = undefined;
				initError = err instanceof Error ? err.message : String(err);
			}
		})();
	}
	return initPromise;
}

/** Test hook: drop the loaded parser (simulates a load failure when `failInit` is set). */
export function resetShellForTests(options: { failInit?: boolean } = {}): void {
	parser = undefined;
	initError = options.failInit ? "simulated parser load failure" : undefined;
	initPromise = options.failInit ? Promise.resolve() : undefined;
}

export function parserReady(): boolean {
	return parser !== undefined;
}

/** Why the parser is unavailable, if it is. */
export function parserError(): string | undefined {
	return initError;
}

// ---------------------------------------------------------------------------
// Static word helpers
// ---------------------------------------------------------------------------

const GLOB_CHARS = /[*?[]/;
/** Unescaped `{a,b}` / `{1..3}`: bash expands these into several words. */
const BRACE_EXPANSION = /(?<!\\)\{[^{}\s]*(?:,|\.\.)[^{}\s]*\}/;

function lit(value: string, text: string = value, glob = false): Word {
	return { value, text, literal: true, expansions: [], glob };
}

function nonLiteral(text: string, expansion: string): Word {
	return { value: text, text, literal: false, expansions: [expansion], glob: false };
}

/** Resolve backslash escapes in an unquoted word and report whether it has an unescaped glob char. */
function unescapeWord(text: string): { value: string; glob: boolean } {
	let value = "";
	let glob = false;
	for (let i = 0; i < text.length; i++) {
		const ch = text[i];
		if (ch === "\\" && i + 1 < text.length) {
			value += text[i + 1];
			i++;
			continue;
		}
		if (GLOB_CHARS.test(ch)) glob = true;
		value += ch;
	}
	return { value, glob };
}

function unescapeDoubleQuoted(text: string): string {
	return text.replace(/\\([$"`\\])|\\\n/g, (_m, c: string | undefined) => c ?? "");
}

const ANSI_SIMPLE: Record<string, string> = {
	n: "\n",
	t: "\t",
	r: "\r",
	a: "\x07",
	b: "\b",
	e: "\x1b",
	E: "\x1b",
	f: "\f",
	v: "\v",
	"\\": "\\",
	"'": "'",
	'"': '"',
	"?": "?",
};

/** Decode `$'…'`; returns undefined for escapes we don't model. */
function decodeAnsiC(text: string): string | undefined {
	const body = text.slice(2, -1);
	let out = "";
	for (let i = 0; i < body.length; i++) {
		const ch = body[i];
		if (ch !== "\\") {
			out += ch;
			continue;
		}
		const next = body[i + 1];
		if (next === undefined) return undefined;
		if (ANSI_SIMPLE[next] !== undefined) {
			out += ANSI_SIMPLE[next];
			i++;
			continue;
		}
		let m = /^x([0-9a-fA-F]{1,2})/.exec(body.slice(i + 1));
		if (m) {
			out += String.fromCharCode(parseInt(m[1], 16));
			i += m[0].length;
			continue;
		}
		m = /^([0-7]{1,3})/.exec(body.slice(i + 1));
		if (m) {
			out += String.fromCharCode(parseInt(m[1], 8));
			i += m[0].length;
			continue;
		}
		m = /^u([0-9a-fA-F]{1,4})/.exec(body.slice(i + 1));
		if (m) {
			out += String.fromCharCode(parseInt(m[1], 16));
			i += m[0].length;
			continue;
		}
		return undefined;
	}
	return out;
}

/** Variables substituted statically in words. Anything else makes the word non-literal. */
function staticVariable(name: string, cwd: string | null): string | undefined {
	switch (name) {
		case "HOME":
			return homeDir();
		case "PWD":
			return cwd ?? undefined;
		case "TMPDIR":
			return process.env.TMPDIR ?? os.tmpdir();
		case "USER":
			try {
				return os.userInfo().username;
			} catch {
				return process.env.USER;
			}
		default:
			return undefined;
	}
}

/** Environment variable names that change how other programs behave: never allow-matched. */
const DANGEROUS_ASSIGNMENT =
	/^(PATH|HOME|IFS|ENV|BASH_ENV|SHELL|SHELLOPTS|BASHOPTS|PS4|PROMPT_COMMAND|CDPATH|LD_.*|DYLD_.*|GIT_.*|NODE_.*|PYTHON.*|PERL.*|RUBY.*|GCONV_PATH|GLIBC_TUNABLES|EDITOR|VISUAL|PAGER|MANPAGER|LESSOPEN|BROWSER|SSH_.*|XDG_.*)$/;

export function isDangerousAssignment(name: string): boolean {
	return DANGEROUS_ASSIGNMENT.test(name);
}

/** Node types the walker knows how to handle. Anything else is recorded as opaque. */
const KNOWN_STATEMENTS = new Set([
	"program",
	"command",
	"pipeline",
	"list",
	"subshell",
	"redirected_statement",
	"negated_command",
	"if_statement",
	"elif_clause",
	"else_clause",
	"for_statement",
	"c_style_for_statement",
	"while_statement",
	"case_statement",
	"case_item",
	"do_group",
	"compound_statement",
	"function_definition",
	"variable_assignment",
	"variable_assignments",
	"declaration_command",
	"unset_command",
	"test_command",
	"comment",
]);

const REDIRECT_TYPES = new Set(["file_redirect", "heredoc_redirect", "herestring_redirect"]);

const SAFE_STATIC_NAMES = new Set(["HOME", "PWD", "TMPDIR", "USER"]);

interface State {
	cwd: string | null;
}

class Analyzer {
	commands: Cmd[] = [];
	paths: PathRef[] = [];
	opaque: string[] = [];

	private src: string;
	private baseCwd: string;

	constructor(src: string, baseCwd: string) {
		this.src = src;
		this.baseCwd = baseCwd;
	}

	private addOpaque(reason: string): void {
		if (!this.opaque.includes(reason)) this.opaque.push(reason);
	}

	// -- words ---------------------------------------------------------------

	/** Sources between named children (quotes excluded by the caller). */
	private joinParts(node: TSNode, from: number, to: number, state: State, decodeGap: (s: string) => string, quoted: boolean): Word {
		let value = "";
		let literal = true;
		let glob = false;
		const expansions: string[] = [];
		let cursor = from;
		for (const child of node.namedChildren) {
			if (child.startIndex < cursor) continue;
			if (child.startIndex > cursor) {
				const gap = this.src.slice(cursor, child.startIndex);
				if (quoted) value += decodeGap(gap);
				else {
					const u = unescapeWord(gap);
					value += u.value;
					glob = glob || u.glob;
				}
			}
			if (child.type === "string_content") {
				value += decodeGap(child.text);
			} else {
				const w = this.word(child, state);
				value += w.value;
				literal = literal && w.literal;
				expansions.push(...w.expansions);
				glob = glob || (!quoted && w.glob);
			}
			cursor = child.endIndex;
		}
		if (cursor < to) {
			const gap = this.src.slice(cursor, to);
			if (quoted) value += decodeGap(gap);
			else {
				const u = unescapeWord(gap);
				value += u.value;
				glob = glob || u.glob;
			}
		}
		return { value, text: this.src.slice(node.startIndex, node.endIndex), literal, expansions, glob: glob && literal };
	}

	word(node: TSNode, state: State): Word {
		switch (node.type) {
			case "word": {
				if (BRACE_EXPANSION.test(node.text)) return nonLiteral(node.text, "brace expansion");
				const u = unescapeWord(node.text);
				return lit(u.value, node.text, u.glob);
			}
			case "number":
				return lit(node.text);
			case "raw_string":
				return lit(node.text.slice(1, -1), node.text);
			case "ansi_c_string": {
				const decoded = decodeAnsiC(node.text);
				return decoded === undefined ? nonLiteral(node.text, "ansi-c string") : lit(decoded, node.text);
			}
			case "string":
			case "translated_string": {
				const open = node.text.startsWith("$") ? 2 : 1;
				return this.joinParts(node, node.startIndex + open, node.endIndex - 1, state, unescapeDoubleQuoted, true);
			}
			case "concatenation": {
				if (BRACE_EXPANSION.test(node.text)) {
					this.scanNested(node, state);
					return nonLiteral(node.text, "brace expansion");
				}
				return this.joinParts(node, node.startIndex, node.endIndex, state, (s) => s, false);
			}
			case "simple_expansion":
			case "expansion": {
				const m = /^\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?$/.exec(node.text);
				if (m && SAFE_STATIC_NAMES.has(m[1])) {
					const v = staticVariable(m[1], state.cwd ?? this.baseCwd);
					if (v !== undefined && (m[1] !== "PWD" || state.cwd !== null)) return lit(v, node.text);
				}
				this.scanNested(node, state);
				return nonLiteral(node.text, node.text);
			}
			case "command_substitution":
			case "process_substitution": {
				this.walkScoped(node, state, true);
				return nonLiteral(node.text, node.text);
			}
			default:
				this.scanNested(node, state);
				return nonLiteral(node.text, node.text);
		}
	}

	/** Find substitutions inside nodes whose words we do not resolve (loops lists, tests, heredocs, …). */
	scanNested(node: TSNode, state: State): void {
		for (const child of node.namedChildren) {
			if (child.type === "command_substitution" || child.type === "process_substitution") {
				this.walkScoped(child, state, true);
			} else {
				this.scanNested(child, state);
			}
		}
	}

	// -- statements ----------------------------------------------------------

	/** Walk a node's children in a copy of the state (cd inside does not leak out). */
	private walkScoped(node: TSNode, state: State, nested: boolean): void {
		const inner: State = { cwd: state.cwd };
		this.walkChildren(node, inner, nested);
	}

	private walkChildren(node: TSNode, state: State, nested: boolean): void {
		const kids = node.children;
		for (let i = 0; i < kids.length; i++) {
			const child = kids[i];
			if (!child.isNamed) continue;
			let j = i + 1;
			while (j < kids.length && kids[j].type === "comment") j++;
			const backgrounded = kids[j]?.type === "&";
			if (backgrounded) this.walk(child, { cwd: state.cwd }, nested);
			else this.walk(child, state, nested);
		}
	}

	/** Run `fn` against a copy of the state; if the cwd changed, it is unknown afterwards. */
	private conditional(state: State, fn: (s: State) => void): void {
		const inner: State = { cwd: state.cwd };
		fn(inner);
		if (inner.cwd !== state.cwd) state.cwd = null;
	}

	walk(node: TSNode, state: State, nested: boolean): void {
		if (node.type === "ERROR" || node.isMissing) {
			this.addOpaque("syntax error");
			this.scanNested(node, state);
			return;
		}
		if (!KNOWN_STATEMENTS.has(node.type)) {
			this.addOpaque(`unsupported syntax: ${node.type}`);
			this.scanNested(node, state);
			return;
		}
		switch (node.type) {
			case "comment":
				return;
			case "program":
			case "do_group":
			case "compound_statement":
			case "negated_command":
				this.walkChildren(node, state, nested);
				return;
			case "command":
				this.command(node, state, nested);
				return;
			case "pipeline":
				// Each element runs in its own subshell.
				for (const child of node.namedChildren) this.walk(child, { cwd: state.cwd }, nested);
				return;
			case "list": {
				const kids = node.namedChildren;
				if (kids.length === 0) return;
				this.walk(kids[0], state, nested);
				for (const rest of kids.slice(1)) this.conditional(state, (s) => this.walk(rest, s, nested));
				return;
			}
			case "subshell":
				this.walkScoped(node, state, true);
				return;
			case "redirected_statement": {
				const body = node.childForFieldName("body");
				if (body) this.walk(body, state, nested);
				for (const child of node.namedChildren) {
					if (REDIRECT_TYPES.has(child.type)) this.redirect(child, state, undefined);
				}
				return;
			}
			case "if_statement":
			case "elif_clause":
			case "else_clause":
			case "while_statement":
			case "case_statement":
			case "case_item":
			case "c_style_for_statement":
				this.conditional(state, (s) => {
					for (const child of node.namedChildren) {
						if (KNOWN_STATEMENTS.has(child.type) || child.type === "ERROR") this.walk(child, s, nested);
						else this.scanNested(child, s);
					}
				});
				return;
			case "for_statement":
				this.conditional(state, (s) => {
					for (const child of node.namedChildren) {
						if (child.type === "do_group") this.walk(child, s, nested);
						else this.scanNested(child, s);
					}
				});
				return;
			case "function_definition": {
				// A function body runs wherever it is called from: cwd unknown.
				const body = node.childForFieldName("body");
				if (body) this.walk(body, { cwd: null }, true);
				return;
			}
			case "variable_assignment":
				this.assignment(node, state);
				return;
			case "variable_assignments":
				for (const child of node.namedChildren) this.assignment(child, state);
				return;
			case "declaration_command":
				for (const child of node.namedChildren) {
					if (child.type === "variable_assignment") this.assignment(child, state);
					else this.scanNested(child, state);
				}
				return;
			case "unset_command":
			case "test_command":
				this.scanNested(node, state);
				return;
		}
	}

	private assignment(node: TSNode, state: State): void {
		const name = node.childForFieldName("name")?.text ?? node.text.split("=")[0];
		const valueNode = node.childForFieldName("value");
		if (valueNode) this.word(valueNode, state);
		if (isDangerousAssignment(name)) this.addOpaque(`assignment to ${name}`);
	}

	private redirect(node: TSNode, state: State, cmdIndex: number | undefined): void {
		if (node.type !== "file_redirect") {
			// heredoc / herestring: data, but may embed substitutions.
			this.scanNested(node, state);
			return;
		}
		const dest = node.childForFieldName("destination");
		if (!dest) return;
		const opText = this.src.slice(node.startIndex, dest.startIndex).trim().replace(/^\d+/, "");
		const w = this.word(dest, state);
		if (/&$/.test(opText) && (/^\d+$/.test(w.value) || w.value === "-")) return; // fd duplication
		const access: PathAccess = opText.includes(">") ? "write" : "read";
		this.paths.push({ word: w, access, source: "redirect", cwd: state.cwd, cmd: cmdIndex });
	}

	private command(node: TSNode, state: State, nested: boolean): void {
		const assignments: Cmd["assignments"] = [];
		const argv: Word[] = [];
		const redirects: TSNode[] = [];
		const cwdAtStart = state.cwd;

		for (const child of node.namedChildren) {
			if (child.type === "variable_assignment") {
				const name = child.childForFieldName("name")?.text ?? child.text.split("=")[0];
				const valueNode = child.childForFieldName("value");
				const value = valueNode ? this.word(valueNode, state) : lit("");
				assignments.push({ name, value });
			} else if (child.type === "command_name") {
				const inner = child.namedChildren[0];
				argv.push(inner ? this.word(inner, state) : lit(child.text));
			} else if (REDIRECT_TYPES.has(child.type)) {
				redirects.push(child);
			} else if (child.type === "comment") {
				continue;
			} else {
				argv.push(this.word(child, state));
			}
		}

		const index = this.commands.length;
		this.commands.push({ argv, assignments, text: node.text, nested, cwd: cwdAtStart });

		const name = argv[0]?.literal ? basename(argv[0].value) : undefined;

		// Path-ish words.
		argv.slice(1).forEach((w, i) => {
			if (name === "cd" && i === 0 && !w.value.startsWith("-")) {
				this.paths.push({ word: w, access: "read", source: "cd", cwd: cwdAtStart, cmd: index });
				return;
			}
			if (w.value.startsWith("-") && w.value.length > 1) {
				const eq = w.value.indexOf("=");
				if (eq > 0 && w.literal) {
					const valueWord: Word = { ...w, value: w.value.slice(eq + 1), text: w.text.slice(w.text.indexOf("=") + 1) };
					this.paths.push({ word: valueWord, access: "unknown", source: "arg", cwd: cwdAtStart, cmd: index, flagValue: true });
				}
				return;
			}
			this.paths.push({ word: w, access: "unknown", source: "arg", cwd: cwdAtStart, cmd: index });
		});

		for (const r of redirects) this.redirect(r, state, index);

		if ((name === "source" || name === ".") && argv[1] && !argv[1].literal) {
			this.addOpaque(`${name} with a non-literal file`);
		}

		// cd tracking.
		if (name === "cd") {
			const operands = argv.slice(1).filter((w) => !(w.value.startsWith("-") && w.value.length > 1));
			const target = operands[0];
			if (argv.slice(1).some((w) => w.value === "-")) state.cwd = null;
			else if (!target) state.cwd = homeDir();
			else if (!target.literal || target.glob) state.cwd = null;
			else {
				const expanded = expandTilde(target.value);
				if (path.isAbsolute(expanded)) state.cwd = path.normalize(expanded);
				else state.cwd = cwdAtStart === null ? null : path.resolve(cwdAtStart, expanded);
			}
		} else if (name === "pushd" || name === "popd") {
			state.cwd = null;
		}
	}
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

function hasMissing(node: TSNode): boolean {
	if (node.isMissing || node.type === "ERROR") return true;
	for (const child of node.children) if (hasMissing(child)) return true;
	return false;
}

/**
 * Analyze a bash command. Uses tree-sitter when the parser is loaded,
 * otherwise the crude fallback tokenizer (flagged `parser: false`).
 */
export function analyze(command: string, cwd: string): Analysis {
	if (!parser) return fallbackAnalyze(command, cwd);
	const tree = parser.parse(command);
	if (!tree) return { ...fallbackAnalyze(command, cwd), opaque: ["parse failed"], parseError: true };
	try {
		const root = tree.rootNode;
		const a = new Analyzer(command, cwd);
		a.walk(root, { cwd }, false);
		const parseError = root.hasError || hasMissing(root);
		const opaque = [...a.opaque];
		let commands = a.commands;
		let paths = a.paths;
		if (parseError) {
			if (!opaque.includes("parse error")) opaque.unshift("parse error");
			// The tree may have lost commands: also scan crudely so denies still fire.
			const crude = fallbackAnalyze(command, cwd);
			commands = [...commands, ...crude.commands];
			paths = [...paths, ...crude.paths.map((p) => ({ ...p, cmd: undefined }))];
		}
		return { commands, paths, opaque, parseError, parser: true };
	} finally {
		tree.delete();
	}
}

// ---------------------------------------------------------------------------
// Fallback tokenizer (parser unavailable / parse error)
// ---------------------------------------------------------------------------

/** Split on shell separators and common nesting syntax, then tokenize each piece with basic quote handling. */
function fallbackSegments(command: string): string[] {
	const pieces: string[] = [];
	let current = "";
	let quote: "'" | '"' | undefined;
	const push = () => {
		if (current.trim().length > 0) pieces.push(current.trim());
		current = "";
	};
	for (let i = 0; i < command.length; i++) {
		const ch = command[i];
		if (quote) {
			current += ch;
			if (ch === quote) quote = undefined;
			else if (ch === "\\" && quote === '"') current += command[++i] ?? "";
			continue;
		}
		if (ch === "'" || ch === '"') {
			quote = ch;
			current += ch;
			continue;
		}
		if (ch === "\\") {
			current += ch + (command[++i] ?? "");
			continue;
		}
		if (ch === ";" || ch === "&" || ch === "|" || ch === "\n" || ch === "`" || ch === "(" || ch === ")") {
			// keep `>&` / `&>` / `2>&1` intact
			if (ch === "&" && (command[i - 1] === ">" || command[i + 1] === ">")) {
				current += ch;
				continue;
			}
			push();
			continue;
		}
		if (ch === "$" && command[i + 1] === "(") {
			push();
			i++;
			continue;
		}
		current += ch;
	}
	push();
	return pieces;
}

function fallbackTokens(segment: string): string[] {
	const tokens: string[] = [];
	let current = "";
	let has = false;
	let quote: "'" | '"' | undefined;
	for (let i = 0; i < segment.length; i++) {
		const ch = segment[i];
		if (quote) {
			if (ch === quote) quote = undefined;
			else if (ch === "\\" && quote === '"' && i + 1 < segment.length) current += segment[++i];
			else current += ch;
			continue;
		}
		if (ch === "'" || ch === '"') {
			quote = ch;
			has = true;
			continue;
		}
		if (ch === "\\" && i + 1 < segment.length) {
			current += segment[++i];
			has = true;
			continue;
		}
		if (/\s/.test(ch)) {
			if (has) tokens.push(current);
			current = "";
			has = false;
			continue;
		}
		current += ch;
		has = true;
	}
	if (has) tokens.push(current);
	return tokens;
}

export function fallbackAnalyze(command: string, cwd: string): Analysis {
	const commands: Cmd[] = [];
	const paths: PathRef[] = [];
	for (const segment of fallbackSegments(command)) {
		const raw = fallbackTokens(segment);
		const words: Word[] = [];
		const redirectTargets: { target: string; access: PathAccess }[] = [];
		for (let i = 0; i < raw.length; i++) {
			const t = raw[i];
			const m = /^(\d*)(>>?|<|&>>?|>\|)(.*)$/.exec(t);
			if (m && !/^&?\d*>&/.test(t)) {
				const target = m[3].length > 0 ? m[3] : (raw[++i] ?? "");
				if (target.length > 0) redirectTargets.push({ target, access: m[2] === "<" ? "read" : "write" });
				continue;
			}
			words.push(lit(t));
		}
		let k = 0;
		while (k < words.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(words[k].value)) k++;
		const stripped = words.slice(k);
		if (stripped.length === 0) continue;
		const index = commands.length;
		commands.push({ argv: stripped, assignments: [], text: segment, nested: false, cwd });
		stripped.slice(1).forEach((w) => {
			if (w.value.startsWith("-") && w.value.length > 1) {
				const eq = w.value.indexOf("=");
				if (eq > 0) paths.push({ word: lit(w.value.slice(eq + 1)), access: "unknown", source: "arg", cwd, cmd: index, flagValue: true });
				return;
			}
			paths.push({ word: { ...w, glob: GLOB_CHARS.test(w.value) }, access: "unknown", source: "arg", cwd, cmd: index });
		});
		for (const r of redirectTargets) paths.push({ word: lit(r.target), access: r.access, source: "redirect", cwd, cmd: index });
	}
	return {
		commands,
		paths,
		opaque: [parserError() ? `bash parser unavailable (${parserError()})` : "bash parser unavailable"],
		parseError: false,
		parser: false,
	};
}
