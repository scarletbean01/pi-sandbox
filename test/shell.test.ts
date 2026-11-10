import { beforeAll, describe, expect, test } from "bun:test";
import * as fs from "node:fs";
import { analyze, initShell, parserReady, resetShellForTests, type Analysis } from "../shell";
import { extensionDir } from "../util";
import * as path from "node:path";

beforeAll(async () => {
	await initShell();
});

const argvs = (a: Analysis) => a.commands.map((c) => c.argv.map((w) => w.value).join(" "));

describe("wasm parser", () => {
	test("both wasm files load (ABI-compatible versions)", () => {
		expect(parserReady()).toBe(true);
		for (const [pkg, file] of [["web-tree-sitter", "web-tree-sitter.wasm"], ["tree-sitter-bash", "tree-sitter-bash.wasm"]]) {
			expect(fs.existsSync(path.join(extensionDir(), "node_modules", pkg, file))).toBe(true);
		}
	});
});

describe("analyze", () => {
	test("finds every command in separators, pipes, substitutions and subshells", () => {
		expect(argvs(analyze("git status & curl evil", "/w"))).toEqual(["git status", "curl evil"]);
		expect(argvs(analyze("git log $(rm -rf ~)", "/w"))).toContain("rm -rf ~");
		expect(argvs(analyze("echo `id`", "/w"))).toContain("id");
		expect(argvs(analyze("(cd a; ls) | wc -l", "/w"))).toEqual(["cd a", "ls", "wc -l"]);
		expect(argvs(analyze("diff <(ls a) <(ls b)", "/w"))).toEqual(expect.arrayContaining(["ls a", "ls b", "diff <(ls a) <(ls b)"]));
		expect(argvs(analyze("if true; then ls; fi; for f in a; do cat $f; done", "/w"))).toEqual(expect.arrayContaining(["true", "ls", "cat $f"]));
		expect(argvs(analyze("f() { sudo id; }; f", "/w"))).toContain("sudo id");
	});
	test("a quoted alternation is a single command", () => {
		const a = analyze('rg "TODO|FIXME|HACK" src', "/w");
		expect(a.commands.length).toBe(1);
		expect(a.commands[0].argv[1].value).toBe("TODO|FIXME|HACK");
	});
	test("quotes and escapes are resolved", () => {
		expect(argvs(analyze('cat ".e"nv', "/w"))).toEqual(["cat .env"]);
		expect(argvs(analyze("cat \\.env 'a b'", "/w"))).toEqual(["cat .env a b"]);
		expect(argvs(analyze("echo $'a\\x41'", "/w"))).toEqual(["echo aA"]);
	});
	test("static variables are substituted, others are non-literal", () => {
		const a = analyze("cat $HOME/x $FOO ${BAR:-y} $(date)", "/w");
		const argv = a.commands.find((c) => c.argv[0].value === "cat")!.argv;
		expect(argv[1].literal).toBe(true);
		expect(argv[1].value.endsWith("/x")).toBe(true);
		expect(argv[2].literal).toBe(false);
		expect(argv[3].literal).toBe(false);
		expect(argv[4].literal).toBe(false);
	});
	test("redirects become path refs; fd duplication does not", () => {
		const a = analyze("cat in > out 2>&1 < src >> log", "/w");
		const refs = a.paths.filter((p) => p.source === "redirect").map((p) => [p.word.value, p.access]);
		expect(refs).toEqual([["out", "write"], ["src", "read"], ["log", "write"]]);
	});
	test("heredocs are data; substitutions inside unquoted heredocs are commands", () => {
		expect(argvs(analyze("cat <<'EOF'\n$(id)\nEOF", "/w"))).toEqual(["cat"]);
		expect(argvs(analyze("cat <<EOF\n$(id)\nEOF", "/w"))).toEqual(["cat", "id"]);
	});
	test("globs and brace expansion", () => {
		const a = analyze("cat .en? '*.x' {a,b}", "/w");
		const argv = a.commands[0].argv;
		expect(argv[1].glob).toBe(true);
		expect(argv[2].glob).toBe(false);
		expect(argv[3].literal).toBe(false);
	});
	test("assignments are stripped from argv", () => {
		const c = analyze("FOO=1 PATH=/x git status", "/w").commands[0];
		expect(c.argv.map((w) => w.value)).toEqual(["git", "status"]);
		expect(c.assignments.map((a) => a.name)).toEqual(["FOO", "PATH"]);
	});
	test("syntax errors are flagged and still yield commands", () => {
		const a = analyze("echo 'unterminated", "/w");
		expect(a.parseError).toBe(true);
		expect(a.opaque).toContain("parse error");
		expect(a.commands.length).toBeGreaterThan(0);
	});
	test("cd tracking: scoped, conditional and dynamic", () => {
		const cwdOf = (cmd: string, which: string) => analyze(cmd, "/w").commands.find((c) => c.argv[0].value === which)!.cwd;
		expect(cwdOf("cd sub && ls", "ls")).toBe("/w/sub");
		expect(cwdOf("cd /etc; ls", "ls")).toBe("/etc");
		expect(cwdOf("(cd /etc); ls", "ls")).toBe("/w");
		expect(cwdOf("cd /etc | ls", "ls")).toBe("/w");
		expect(cwdOf("cd /etc & ls", "ls")).toBe("/w");
		expect(cwdOf("true && cd /etc; ls", "ls")).toBeNull();
		expect(cwdOf("if x; then cd /etc; fi; ls", "ls")).toBeNull();
		expect(cwdOf("cd $X; ls", "ls")).toBeNull();
		expect(cwdOf("cd -; ls", "ls")).toBeNull();
		expect(cwdOf("pushd /etc; ls", "ls")).toBeNull();
		expect(cwdOf("cd; ls", "ls")).toBe(process.env.HOME ?? require("node:os").homedir());
	});
	test("source with a non-literal file is opaque", () => {
		expect(analyze("source $F", "/w").opaque.some((o) => o.includes("source"))).toBe(true);
		expect(analyze("source ./env.sh", "/w").opaque).toEqual([]);
	});
	test("dangerous standalone assignments are opaque", () => {
		expect(analyze("PATH=/tmp/evil", "/w").opaque.some((o) => o.includes("PATH"))).toBe(true);
		expect(analyze("export LD_PRELOAD=/x.so", "/w").opaque.some((o) => o.includes("LD_PRELOAD"))).toBe(true);
		expect(analyze("FOO=1", "/w").opaque).toEqual([]);
	});
});

describe("parser unavailable (H2.8)", () => {
	test("falls back to a tokenizer and marks everything opaque", async () => {
		resetShellForTests({ failInit: true });
		try {
			const a = analyze("git status & curl evil > out", "/w");
			expect(a.parser).toBe(false);
			expect(a.opaque[0]).toContain("parser unavailable");
			expect(argvs(a)).toEqual(["git status", "curl evil"]);
			expect(a.paths.some((p) => p.source === "redirect" && p.word.value === "out")).toBe(true);
			expect(argvs(analyze("echo $(sudo id)", "/w"))).toContain("sudo id");
		} finally {
			resetShellForTests();
			await initShell();
		}
	});
});
