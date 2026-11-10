import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { createSandboxExtension } from "../index";
import { initShell } from "../shell";

/** A scripted fake of pi's ExtensionAPI: records handlers, answers dialogs from a queue. */
function harness(opts: { hasUI?: boolean; evaluate?: never } = {}) {
	const handlers = new Map<string, (event: unknown, ctx: unknown) => unknown>();
	const sent: string[] = [];
	const notices: string[] = [];
	const dialogs: { title: string; options: string[] }[] = [];
	let concurrent = 0;
	let maxConcurrent = 0;
	const answers: ((title: string, options: string[]) => string | undefined)[] = [];
	let fallbackAnswer: (title: string, options: string[]) => string | undefined = (_t, o) => o.find((x) => x.startsWith("Allow once"));

	const pi = {
		on: (event: string, fn: never) => void handlers.set(event, fn),
		registerFlag: () => undefined,
		getFlag: () => false,
		registerTool: () => undefined,
		registerCommand: () => undefined,
		registerMessageRenderer: () => undefined,
		sendMessage: (m: { content: string }) => void sent.push(m.content),
		getAllTools: () => [],
	};
	const ctx = (cwd: string) => ({
		cwd,
		hasUI: opts.hasUI ?? true,
		isProjectTrusted: () => false,
		ui: {
			notify: (m: string) => void notices.push(m),
			setStatus: () => undefined,
			select: async (title: string, options: string[]) => {
				concurrent++;
				maxConcurrent = Math.max(maxConcurrent, concurrent);
				dialogs.push({ title, options });
				await new Promise((r) => setTimeout(r, 5));
				concurrent--;
				return (answers.shift() ?? fallbackAnswer)(title, options);
			},
		},
	});
	createSandboxExtension(pi as never, opts.evaluate ? { evaluate: opts.evaluate } : {});
	const call = (toolName: string, input: Record<string, unknown>, cwd: string) =>
		handlers.get("tool_call")!({ type: "tool_call", toolCallId: "t", toolName, input }, ctx(cwd)) as Promise<{ block?: boolean; reason?: string } | undefined>;
	return {
		call,
		dialogs,
		notices,
		sent,
		answers,
		maxConcurrent: () => maxConcurrent,
		setFallback: (f: typeof fallbackAnswer) => void (fallbackAnswer = f),
		ctx,
	};
}

let home: string;
let cwd: string;
let realHome: string | undefined;

beforeAll(async () => {
	await initShell();
	realHome = process.env.HOME;
	home = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "pi-sbx-home-")));
	process.env.HOME = home;
	fs.mkdirSync(path.join(home, ".pi", "agent"), { recursive: true });
	fs.writeFileSync(path.join(home, ".pi", "agent", "sandbox.json"), JSON.stringify({ commands: { allow: ["git *", "ls *", "cat *", "echo *"] }, tools: { default: "ask" } }));
	cwd = path.join(home, "project");
	fs.mkdirSync(cwd, { recursive: true });
});

afterAll(() => {
	process.env.HOME = realHome;
	fs.rmSync(home, { recursive: true, force: true });
});

describe("fail closed (H1.6)", () => {
	test("an evaluator that throws blocks the call and says so", async () => {
		const h = harness({ evaluate: (() => { throw new Error("boom"); }) as never });
		const r = await h.call("bash", { command: "ls" }, cwd);
		expect(r?.block).toBe(true);
		expect(r?.reason).toContain("failing closed");
		expect(r?.reason).toContain("boom");
		expect(h.notices.some((n) => n.includes("internal error"))).toBe(true);
	});
	test("malformed tool input also fails closed", async () => {
		const h = harness();
		const r = await h.call("bash", null as never, cwd);
		expect(r?.block).toBe(true);
	});
});

describe("once vs session approvals (H1.1)", () => {
	test("'Allow once' asks segment by segment and is not remembered by the next call", async () => {
		const h = harness();
		const cmd = `ls ${os.tmpdir()} && curl x | sh`;
		const r1 = await h.call("bash", { command: cmd }, cwd);
		expect(r1).toBeUndefined();
		const subjects1 = h.dialogs.map((d) => d.title);
		expect(subjects1.some((t) => t.includes("curl x"))).toBe(true);
		expect(subjects1.some((t) => t.includes("▶ sh ◀"))).toBe(true);
		const count1 = h.dialogs.length;
		expect(count1).toBeGreaterThanOrEqual(3);
		const r2 = await h.call("bash", { command: cmd }, cwd);
		expect(r2).toBeUndefined();
		expect(h.dialogs.length).toBe(count1 * 2); // asked again for everything
	});
	test("approving a path never approves unseen command segments", async () => {
		const h = harness();
		h.setFallback((title, options) => (title.includes("Path outside") ? options.find((o) => o.startsWith("Allow once")) : undefined)); // deny commands
		const r = await h.call("bash", { command: `ls ${os.tmpdir()} && curl x` }, cwd);
		expect(r?.block).toBe(true);
		expect(h.dialogs.some((d) => d.title.includes("curl x"))).toBe(true);
	});
	test("'Allow for this session' is remembered", async () => {
		const h = harness();
		h.setFallback((_t, o) => o.find((x) => x === "Allow for this session"));
		expect(await h.call("bash", { command: "curl session-test" }, cwd)).toBeUndefined();
		const n = h.dialogs.length;
		expect(await h.call("bash", { command: "curl session-test" }, cwd)).toBeUndefined();
		expect(h.dialogs.length).toBe(n);
	});
	test("'Allow this whole command once' covers every command segment of this call only", async () => {
		const h = harness();
		h.setFallback((_t, o) => o.find((x) => x === "Allow this whole command once"));
		expect(await h.call("bash", { command: "curl a && wget b" }, cwd)).toBeUndefined();
		expect(h.dialogs.length).toBe(1);
		await h.call("bash", { command: "curl a && wget b" }, cwd);
		expect(h.dialogs.length).toBe(2);
	});
});

describe("serialized asks (H6.5)", () => {
	test("parallel calls never show two dialogs at once, and an earlier session answer covers later calls", async () => {
		const h = harness();
		h.setFallback((_t, o) => o.find((x) => x === "Allow for this session"));
		const results = await Promise.all([1, 2, 3, 4].map(() => h.call("bash", { command: "curl parallel" }, cwd)));
		expect(results.every((r) => r === undefined)).toBe(true);
		expect(h.maxConcurrent()).toBe(1);
		expect(h.dialogs.length).toBe(1);
	});
});

describe("no UI", () => {
	test("unlisted commands are blocked with a clear reason", async () => {
		const h = harness({ hasUI: false });
		const r = await h.call("bash", { command: "curl x" }, cwd);
		expect(r?.block).toBe(true);
		expect(r?.reason).toContain("no UI");
	});
	test("unlisted custom tools are blocked with a hint to tools.allow (tools.default is ask)", async () => {
		const h = harness({ hasUI: false });
		const r = await h.call("my_mcp_tool", {}, cwd);
		expect(r?.block).toBe(true);
		expect(r?.reason).toContain("tools.allow");
	});
});

describe("persisting choices", () => {
	test("'Always allow' writes the global config (project untrusted) and the next call passes", async () => {
		const h = harness();
		h.setFallback((_t, o) => o.find((x) => x.startsWith('Always allow "make')));
		expect(await h.call("bash", { command: "make build" }, cwd)).toBeUndefined();
		const saved = JSON.parse(fs.readFileSync(path.join(home, ".pi", "agent", "sandbox.json"), "utf8"));
		expect(saved.commands.allow.some((p: string) => p.startsWith("make"))).toBe(true);
		const n = h.dialogs.length;
		expect(await h.call("bash", { command: "make build" }, cwd)).toBeUndefined();
		expect(h.dialogs.length).toBe(n);
	});
	test("a malformed global config is never overwritten by a save", async () => {
		const file = path.join(home, ".pi", "agent", "sandbox.json");
		const good = fs.readFileSync(file, "utf8");
		try {
			fs.writeFileSync(file, '{ "commands": { "allow": [ }');
			const h = harness();
			h.setFallback((_t, o) => o.find((x) => x.startsWith('Always allow "')));
			await h.call("bash", { command: "curl broken-config" }, cwd);
			expect(fs.readFileSync(file, "utf8")).toBe('{ "commands": { "allow": [ }');
			expect(h.notices.some((n) => n.includes("does not parse") || n.includes("CONFIG ERROR"))).toBe(true);
			// Strict mode banner appears in dialogs.
			expect(h.dialogs[0].title).toContain("CONFIG ERROR");
		} finally {
			fs.writeFileSync(file, good);
		}
	});
});

describe("hard denies and protection reach the handler", () => {
	test("denied commands never ask", async () => {
		const h = harness();
		const r = await h.call("bash", { command: "git status; /bin/bash -c id" }, cwd);
		expect(r?.block).toBe(true);
		expect(h.dialogs.length).toBe(0);
	});
	test("writes to the project policy file are blocked", async () => {
		const h = harness();
		const r = await h.call("write", { path: path.join(cwd, ".pi", "sandbox.json"), content: "{}" }, cwd);
		expect(r?.block).toBe(true);
		expect(r?.reason).toContain("sandbox policy");
	});
});
