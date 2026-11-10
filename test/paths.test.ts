import { describe, expect, test } from "bun:test";
import * as fs from "node:fs";
import * as path from "node:path";
import { checkPath, normalizePath, realpathDeep } from "../paths";
import { computeProtectedWritePaths, DEFAULT_CONFIG } from "../config";
import { withTempProject } from "./helpers";

const { allow, deny } = DEFAULT_CONFIG.paths;

describe("symlinked parents", () => {
	test("realpathDeep resolves through a symlink for not-yet-existing tails", async () => {
		await withTempProject((fx) => {
			expect(realpathDeep(path.join(fx.cwd, "link", "new", "file.txt"))).toBe(path.join(fx.outside, "new", "file.txt"));
			expect(normalizePath("link/newfile", fx.cwd)).toBe(path.join(fx.outside, "newfile"));
		});
	});
	test("allow requires the real path: link/newfile asks and shows the target", async () => {
		await withTempProject((fx) => {
			const r = checkPath("link/newfile", allow, deny, fx.cwd);
			expect(r.verdict).toBe("ask");
			expect(r.subject).toBe(path.join(fx.outside, "newfile"));
		});
	});
	test("a deny on the LEXICAL path wins even when the real path is clean", async () => {
		await withTempProject((fx) => {
			const real = fs.mkdtempSync(path.join(fx.cwd, "realdir-"));
			fs.symlinkSync(real, path.join(fx.cwd, ".ssh"));
			expect(checkPath(".ssh/id", allow, deny, fx.cwd).verdict).toBe("deny");
		});
	});
	test("a cwd reached through a symlink still matches ./**", async () => {
		await withTempProject((fx) => {
			const alias = path.join(path.dirname(fx.cwd), "alias");
			fs.symlinkSync(fx.cwd, alias);
			expect(checkPath("src/main.ts", allow, deny, alias).verdict).toBe("allow");
		});
	});
});

describe("protected paths and safe devices", () => {
	test("protected paths deny writes but allow reads", async () => {
		await withTempProject((fx) => {
			const protectedWrite = computeProtectedWritePaths(fx.cwd, false);
			expect(checkPath(".pi/sandbox.json", allow, deny, fx.cwd, { access: "write", protectedWrite }).protected).toBe(true);
			expect(checkPath(".pi/sandbox.json", allow, deny, fx.cwd, { access: "unknown", protectedWrite }).verdict).toBe("deny");
			expect(checkPath(".pi/sandbox.json", allow, deny, fx.cwd, { access: "read", protectedWrite }).verdict).toBe("allow");
			expect(checkPath(".pi/sandbox.json.bak", allow, deny, fx.cwd, { access: "write", protectedWrite }).verdict).toBe("deny");
		});
	});
	test("/dev/null is always fine", () => {
		expect(checkPath("/dev/null", allow, deny, "/tmp").verdict).toBe("allow");
	});
	test("deny patterns beat allow", async () => {
		await withTempProject((fx) => {
			expect(checkPath(".env", allow, deny, fx.cwd).verdict).toBe("deny");
			expect(checkPath("server.pem", allow, deny, fx.cwd).verdict).toBe("deny");
			expect(checkPath("src/main.ts", allow, deny, fx.cwd).verdict).toBe("allow");
		});
	});
});
