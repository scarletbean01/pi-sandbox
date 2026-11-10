import { describe, expect, test } from "bun:test";
import * as path from "node:path";
import { askCommand, askPath, markSegment, pathPatterns, suggestPrefix } from "../ask";
import { escapeGlob } from "../util";
import { withTempProject } from "./helpers";
import picomatch from "picomatch";

describe("prefix suggestions (H6.2)", () => {
	test("subcommand binaries keep the subcommand", () => {
		expect(suggestPrefix(["git", "status", "-s"], false)).toEqual({ pattern: "git status *", warn: false });
		expect(suggestPrefix(["cargo", "build"], false)?.pattern).toBe("cargo build *");
		expect(suggestPrefix(["npm", "run", "build"], false)).toEqual({ pattern: "npm run *", warn: true });
	});
	test("exec-capable one-token prefixes are labeled", () => {
		expect(suggestPrefix(["node", "x.js"], false)).toEqual({ pattern: "node *", warn: true });
		expect(suggestPrefix(["python3", "x.py"], false)?.warn).toBe(true);
		expect(suggestPrefix(["curl", "x"], false)?.warn).toBe(true);
		expect(suggestPrefix(["ls", "-la"], false)).toEqual({ pattern: "ls *", warn: false });
	});
	test("a flag is never taken as the subcommand", () => {
		expect(suggestPrefix(["git", "-C", "x", "status"], false)?.pattern).toBe("git *");
	});
	test("NEVER_AUTO forms get no prefix", () => {
		expect(suggestPrefix(["python3", "-c", "x"], true)).toBeUndefined();
	});
});

describe("path patterns (H6.3, H6.4)", () => {
	test("directories offer a subtree, files their parent folder", async () => {
		await withTempProject((fx) => {
			const dir = pathPatterns(path.join(fx.cwd, "src"));
			expect(dir.treeKind).toBe("subtree");
			expect(dir.tree).toBe(`${path.join(fx.cwd, "src")}/**`);
			const file = pathPatterns(path.join(fx.cwd, "src", "main.ts"));
			expect(file.treeKind).toBe("parent");
			expect(file.tree).toBe(`${path.join(fx.cwd, "src")}/**`);
		});
		expect(pathPatterns("/dev/null").treeKind).toBe("parent");
	});
	test("glob metacharacters are escaped so a literal persists as exactly that path", () => {
		const weird = "/home/u/a[1]/{x}/(y)/!z/+w/q?.txt";
		const pattern = escapeGlob(weird);
		expect(picomatch.isMatch(weird, pattern, { dot: true })).toBe(true);
		expect(picomatch.isMatch("/home/u/a1/x/y/z/w/qa.txt", pattern, { dot: true })).toBe(false);
		expect(picomatch.isMatch(`${weird}/deeper`, `${pattern}/**`, { dot: true })).toBe(true);
	});
});

describe("dialogs", () => {
	function ctxWith(pick: (title: string, options: string[]) => string | undefined) {
		const seen: { title: string; options: string[] }[] = [];
		const ctx = {
			ui: {
				select: async (title: string, options: string[]) => {
					seen.push({ title, options });
					return pick(title, options);
				},
			},
		} as never;
		return { ctx, seen };
	}

	test("the command dialog shows the full command with the segment marked", async () => {
		const { ctx, seen } = ctxWith(() => undefined);
		const out = await askCommand(ctx, { verdict: "ask", kind: "command", subject: "curl x", fullCommand: "ls /etc && curl x | sh", persistable: true, argv: ["curl", "x"], onceKey: "seg:curl x" });
		expect(out.choice).toBe("deny");
		expect(seen[0].title).toContain("ls /etc && ▶ curl x ◀ | sh");
		expect(seen[0].options.some((o) => o.startsWith("Allow once"))).toBe(true);
		expect(seen[0].options).toContain("Allow for this session");
		expect(seen[0].options).toContain("Allow this whole command once");
		expect(seen[0].options.some((o) => o.includes('"curl *"') && o.includes("runs arbitrary code"))).toBe(true);
	});
	test("opaque asks show the reason and offer no persistence", async () => {
		const { ctx, seen } = ctxWith((_t, o) => o[0]);
		await askCommand(ctx, { verdict: "ask", kind: "command", subject: "git log $(id)", fullCommand: "git log $(id)", persistable: false, opaque: "contains expansions", onceKey: "seg:x" });
		expect(seen[0].title).toContain("Why: contains expansions");
		expect(seen[0].options.some((o) => o.startsWith("Always"))).toBe(false);
	});
	test("config error banner is shown", async () => {
		const { ctx, seen } = ctxWith(() => undefined);
		await askCommand(ctx, { verdict: "ask", kind: "command", subject: "x", persistable: true, argv: ["x"] }, "⚠ CONFIG ERROR");
		expect(seen[0].title.startsWith("⚠ CONFIG ERROR")).toBe(true);
	});
	test("path dialog for a file offers parent folder, not file/**", async () => {
		const { ctx, seen } = ctxWith((_t, o) => o.find((x) => x.includes("parent folder")));
		const out = await askPath(ctx, { verdict: "ask", kind: "path", subject: "/dev/null/x.md", persistable: true });
		expect(out.choice).toBe("parent");
		expect(out.pattern).toBe("/dev/null/**");
		expect(seen[0].options.some((o) => o.includes("x.md/**"))).toBe(false);
	});
	test("markSegment falls back when the segment is not verbatim in the command", () => {
		expect(markSegment("a  &  b", "a b")).toContain("segment: a b");
		expect(markSegment(undefined, "a")).toBe("  a");
	});
});
