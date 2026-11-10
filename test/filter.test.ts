import { describe, expect, test } from "bun:test";
import * as fs from "node:fs";
import * as path from "node:path";
import { createEditTool } from "@earendil-works/pi-coding-agent";
import { filterListing } from "../filter";
import { evaluate } from "../policy";
import { DEFAULT_CONFIG } from "../config";
import { CORPUS_CONFIG, stateWith, withTempProject } from "./helpers";

const { deny } = DEFAULT_CONFIG.paths;
const text = (s: string) => [{ type: "text", text: s }];

describe("tool_result filtering (F12)", () => {
	test("grep results from denied files are dropped and counted", async () => {
		await withTempProject((fx) => {
			const out = filterListing(
				"grep",
				{ path: "." },
				text(["src/main.ts:1: KEY=a", ".env:1: KEY=secret", "server.pem-3- KEY", "src/x.ts:2: KEY=b"].join("\n")),
				deny,
				fx.cwd,
			);
			expect(out?.hidden).toBe(2);
			const body = out!.content.map((b) => b.text).join("\n");
			expect(body).toContain("src/main.ts:1: KEY=a");
			expect(body).toContain("src/x.ts:2: KEY=b");
			expect(body).not.toContain("secret");
			expect(body).not.toContain("server.pem");
			expect(body).toContain("[sandbox: 2 results hidden by deny policy]");
		});
	});
	test("ls and find entries are filtered, directories included", async () => {
		await withTempProject((fx) => {
			fs.mkdirSync(path.join(fx.cwd, ".ssh"));
			const ls = filterListing("ls", { path: "." }, text([".env", ".git/", ".ssh/", "link/", "src/", "[100 entries limit reached]"].join("\n")), deny, fx.cwd);
			const body = ls!.content.map((b) => b.text).join("\n");
			expect(ls?.hidden).toBe(3);
			expect(body).toContain("src/");
			expect(body).toContain("[100 entries limit reached]");
			expect(body).not.toContain(".env");
			const find = filterListing("find", { path: "src" }, text("main.ts\n../.env"), deny, fx.cwd);
			expect(find?.hidden).toBe(1);
		});
	});
	test("nothing hidden → undefined; other tools are untouched", async () => {
		await withTempProject((fx) => {
			expect(filterListing("grep", {}, text("src/a.ts:1: x"), deny, fx.cwd)).toBeUndefined();
			expect(filterListing("read", {}, text(".env:1: x"), deny, fx.cwd)).toBeUndefined();
		});
	});
	test("grep over a single file resolves relative to its directory", async () => {
		await withTempProject((fx) => {
			const out = filterListing("grep", { path: "server.pem" }, text("server.pem:1: x"), deny, fx.cwd);
			expect(out?.hidden).toBe(1);
		});
	});
});

describe("grep/find glob inputs (H3.3)", () => {
	test("a glob that selects only denied files is denied outright", async () => {
		await withTempProject((fx) => {
			const state = stateWith(CORPUS_CONFIG, { cwd: fx.cwd });
			for (const glob of [".env", "**/.env", "*.pem", "id_rsa*"]) {
				expect(evaluate("grep", { pattern: "x", glob }, state).verdict).toBe("deny");
			}
			expect(evaluate("find", { pattern: "*.pem" }, state).verdict).toBe("deny");
			expect(evaluate("grep", { pattern: "x", glob: "*.ts" }, state).verdict).toBe("allow");
			expect(evaluate("find", { pattern: "*.ts" }, state).verdict).toBe("allow");
		});
	});
});

describe("edit tool schema (H3.4)", () => {
	test("the only path-bearing input of edit is `path`", () => {
		const tool = createEditTool(process.cwd());
		const params = tool.parameters as { properties: Record<string, { type?: string; items?: { properties?: Record<string, unknown> } }> };
		expect(Object.keys(params.properties).sort()).toEqual(["edits", "path"]);
		expect(Object.keys(params.properties.edits.items?.properties ?? {}).sort()).toEqual(["newText", "oldText"]);
	});
	test("write / read / grep / find / ls schemas keep their path-ish keys", async () => {
		const { createWriteTool, createReadTool, createGrepTool, createFindTool, createLsTool } = await import("@earendil-works/pi-coding-agent");
		const keys = (t: { parameters: unknown }) => Object.keys((t.parameters as { properties: object }).properties).sort();
		expect(keys(createWriteTool(process.cwd()))).toEqual(["content", "path"]);
		expect(keys(createReadTool(process.cwd()))).toContain("path");
		expect(keys(createGrepTool(process.cwd()))).toEqual(["context", "glob", "ignoreCase", "limit", "literal", "path", "pattern"]);
		expect(keys(createFindTool(process.cwd()))).toEqual(["limit", "path", "pattern"]);
		expect(keys(createLsTool(process.cwd()))).toEqual(["limit", "path"]);
	});
});

describe("end to end with the real pi tools (F12)", () => {
	test("grep/find/ls output is filtered after the real tool ran", async () => {
		const { createGrepTool, createFindTool, createLsTool } = await import("@earendil-works/pi-coding-agent");
		await withTempProject(async (fx) => {
			fs.writeFileSync(path.join(fx.cwd, "src", "notes.txt"), "SECRET=ok\n");
			const run = async (tool: { execute: (...a: never[]) => Promise<{ content: unknown }> }, input: Record<string, unknown>) =>
				((await (tool.execute as (id: string, i: unknown, s?: AbortSignal) => Promise<{ content: { type: string; text?: string }[] }>)("t", input)).content);

			const grep = await run(createGrepTool(fx.cwd) as never, { pattern: "SECRET", path: "." });
			const raw = grep.map((b) => b.text).join("\n");
			expect(raw).toContain(".env:1:"); // the unfiltered tool does leak it
			const filtered = filterListing("grep", { pattern: "SECRET", path: "." }, grep, deny, fx.cwd);
			const body = filtered!.content.map((b) => b.text).join("\n");
			expect(body).not.toContain(".env");
			expect(body).toContain("notes.txt:1: SECRET=ok");

			const ls = await run(createLsTool(fx.cwd) as never, { path: "." });
			expect(ls.map((b) => b.text).join("\n")).toContain(".env");
			const lsFiltered = filterListing("ls", { path: "." }, ls, deny, fx.cwd)!;
			const lsBody = lsFiltered.content.map((b) => b.text).join("\n");
			expect(lsBody).not.toContain(".env");
			expect(lsBody).not.toContain(".git/");
			expect(lsBody).toContain("src/");

			const find = await run(createFindTool(fx.cwd) as never, { pattern: "*", path: "." });
			const findFiltered = filterListing("find", { pattern: "*", path: "." }, find, deny, fx.cwd);
			const findBody = (findFiltered?.content ?? find).map((b) => b.text).join("\n");
			expect(findBody).not.toContain("server.pem");
			expect(findBody).not.toMatch(/(^|\n)\.env($|\n)/);
		});
	});
});
