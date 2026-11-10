import { describe, expect, test } from "bun:test";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import {
	DEFAULT_CONFIG,
	applyStrict,
	computeProtectedWritePaths,
	mergeConfigs,
	mergeConfigsDetailed,
	parseConfigFile,
	stripJsonComments,
	validateConfig,
	writeConfigUpdate,
} from "../config";

function tmpFile(content?: string): { file: string; dir: string } {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pi-sbx-cfg-"));
	const file = path.join(dir, "sandbox.json");
	if (content !== undefined) fs.writeFileSync(file, content);
	return { file, dir };
}

describe("stripJsonComments", () => {
	test("comment markers inside strings survive", () => {
		const out = stripJsonComments('{ "a": "dd *of=/dev/*", // note\n "b": 1 /* x */ }');
		expect(JSON.parse(out)).toEqual({ a: "dd *of=/dev/*", b: 1 });
	});
});

describe("mergeConfigs layering", () => {
	test("lists concatenate defaults < global < project", () => {
		const c = mergeConfigs(
			{ commands: { allow: ["g *"], deny: [] } },
			{ commands: { allow: ["p *"], deny: [] } },
			{ cwd: "/work" },
		);
		expect(c.commands.allow).toEqual(["g *", "p *"]);
		expect(c.paths.allow[0]).toBe("./**");
	});
	test("hard denies are always present", () => {
		expect(mergeConfigs(undefined, undefined).commands.deny).toContain("sudo *");
	});
	test("proxies come from global only", () => {
		expect(mergeConfigs({ commands: { allow: [], deny: [], proxies: [] } }, { commands: { allow: [], deny: [], proxies: ["x"] } }).commands.proxies).toEqual([]);
	});
	test("defaults: tools.default is ask", () => {
		expect(DEFAULT_CONFIG.tools.default).toBe("ask");
	});
});

describe("project config may only tighten", () => {
	const loosening = {
		mode: "off" as const,
		tools: { allow: [], deny: [], default: "allow" as const },
		bwrap: { enabled: false, autoAllow: true, network: "allow" as const, fallback: "ask" as const, allowSockets: ["/run/docker.sock"], allowWrite: ["/etc", "build"] },
		selfEdit: true,
	};
	test("loosening is ignored with warnings", () => {
		const { config, warnings } = mergeConfigsDetailed({ bwrap: { network: "off", fallback: "block" } }, loosening, { cwd: "/work" });
		expect(config.mode).toBe("enforce");
		expect(config.tools.default).toBe("ask");
		expect(config.bwrap.enabled).toBe(true);
		expect(config.bwrap.autoAllow).toBe(false);
		expect(config.bwrap.network).toBe("off");
		expect(config.bwrap.fallback).toBe("block");
		expect(config.bwrap.allowSockets).toEqual([]);
		expect(config.bwrap.allowWrite).not.toContain("/etc");
		expect(config.bwrap.allowWrite).toContain("build");
		expect(config.selfEdit).toBe(false);
		expect(warnings.some((w) => w.includes('"mode: \\"off\\""') || w.includes("mode"))).toBe(true);
		expect(warnings.length).toBeGreaterThanOrEqual(8);
	});
	test("tightening is honored", () => {
		const c = mergeConfigs(undefined, { mode: "enforce", bwrap: { network: "off", fallback: "block" } }, { cwd: "/work" });
		expect(c.bwrap.network).toBe("off");
		expect(c.bwrap.fallback).toBe("block");
	});
	test("allowProjectLoosening (global) is the escape hatch", () => {
		const c = mergeConfigs({ allowProjectLoosening: true }, loosening, { cwd: "/work" });
		expect(c.mode).toBe("off");
		expect(c.bwrap.enabled).toBe(false);
	});
	test("project allow lists still add on top", () => {
		const c = mergeConfigs(undefined, { commands: { allow: ["make *"], deny: [] }, paths: { allow: ["/data/**"], deny: [] } }, { cwd: "/work" });
		expect(c.commands.allow).toContain("make *");
		expect(c.paths.allow).toContain("/data/**");
	});
});

describe("strict fail-closed defaults", () => {
	test("applyStrict is never looser than the defaults", () => {
		const c = applyStrict(mergeConfigs({ mode: "off", tools: { allow: [], deny: [], default: "allow" }, bwrap: { autoAllow: true, fallback: "ask" } }, undefined));
		expect(c.mode).toBe("enforce");
		expect(c.tools.default).toBe("ask");
		expect(c.bwrap.autoAllow).toBe(false);
		expect(c.bwrap.fallback).toBe("block");
		expect(c.commands.deny).toContain("sudo *");
	});
});

describe("parseConfigFile", () => {
	test("reports line and column for malformed JSON", () => {
		const { file } = tmpFile('{\n  "mode": "enforce",\n  "tools": { "allow": [ }\n}\n');
		const r = parseConfigFile(file);
		expect(r.error).toBeDefined();
		expect(r.error?.line).toBe(3);
		expect(r.config).toBeUndefined();
	});
	test("missing file is not an error", () => {
		const r = parseConfigFile("/nonexistent/sandbox.json");
		expect(r.error).toBeUndefined();
		expect(r.config).toBeUndefined();
	});
	test("comments and trailing commas are tolerated", () => {
		const { file } = tmpFile('{ // c\n "commands": { "allow": ["ls *",], }, }');
		expect(parseConfigFile(file).config?.commands?.allow).toEqual(["ls *"]);
	});
});

describe("validateConfig warnings", () => {
	test("unknown keys, wrong types and bad enums warn", () => {
		const { config, warnings } = validateConfig({
			alow: [],
			mode: "sometimes",
			commands: { allow: "git *" },
			bwrap: { network: "maybe", enabled: "yes", allowWrite: [1] },
			paths: { allow: ["["] },
		});
		expect(config.mode).toBeUndefined();
		const text = warnings.join("\n");
		expect(text).toContain('unknown key "alow"');
		expect(text).toContain('"mode"');
		expect(text).toContain("commands.allow");
		expect(text).toContain("bwrap.network");
		expect(text).toContain("bwrap.enabled");
		expect(text).toContain("bwrap.allowWrite");
	});
	test("a clean config has no warnings", () => {
		expect(validateConfig({ commands: { allow: ["git *"], deny: [] }, bwrap: { network: "off" } }).warnings).toEqual([]);
	});
});

describe("writeConfigUpdate", () => {
	test("keeps comments and formatting and writes a .bak", () => {
		const original = '{\n  // my notes\n  "commands": {\n    "allow": [\n      "ls *" // listing\n    ]\n  }\n}\n';
		const { file } = tmpFile(original);
		writeConfigUpdate(file, { kind: "command", pattern: "git status *" });
		const out = fs.readFileSync(file, "utf8");
		expect(out).toContain("// my notes");
		expect(out).toContain("// listing");
		expect(out).toContain('"git status *"');
		expect(fs.readFileSync(`${file}.bak`, "utf8")).toBe(original);
		expect(parseConfigFile(file).config?.commands?.allow).toEqual(["ls *", "git status *"]);
		expect(fs.existsSync(`${file}.tmp`)).toBe(false);
	});
	test("creates sections and files that do not exist", () => {
		const { dir } = tmpFile();
		const file = path.join(dir, "nested", "sandbox.json");
		writeConfigUpdate(file, { kind: "path", pattern: "/data/**" });
		expect(parseConfigFile(file).config?.paths?.allow).toEqual(["/data/**"]);
	});
	test("duplicate patterns are not added twice", () => {
		const { file } = tmpFile('{"tools":{"allow":["x"]}}');
		writeConfigUpdate(file, { kind: "tool", pattern: "x" });
		expect(parseConfigFile(file).config?.tools?.allow).toEqual(["x"]);
	});
	test("refuses to overwrite a malformed file", () => {
		const broken = '{ "commands": { "allow": [ }';
		const { file } = tmpFile(broken);
		expect(() => writeConfigUpdate(file, { kind: "command", pattern: "x" })).toThrow(/does not parse/);
		expect(fs.readFileSync(file, "utf8")).toBe(broken);
	});
	test("mode updates", () => {
		const { file } = tmpFile('{ "mode": "enforce" /* keep */ }');
		writeConfigUpdate(file, { kind: "mode", mode: "off" });
		expect(parseConfigFile(file).config?.mode).toBe("off");
		expect(fs.readFileSync(file, "utf8")).toContain("/* keep */");
	});
});

describe("protected write paths", () => {
	test("policy files, extension dir and git hooks", () => {
		const p = computeProtectedWritePaths("/work/proj", false);
		expect(p.some((x) => x.endsWith("/work/proj/.pi/sandbox.json"))).toBe(true);
		expect(p.some((x) => x.endsWith("/work/proj/.pi/sandbox.json.bak"))).toBe(true);
		expect(p).toContain("/work/proj/.git/config");
		expect(p.some((x) => x.startsWith("/work/proj/.git/hooks"))).toBe(true);
		expect(p.some((x) => x.endsWith("/**") && x.includes("sandbox"))).toBe(true);
	});
	test("selfEdit drops the extension directory", () => {
		const withSelf = computeProtectedWritePaths("/work/proj", true);
		const without = computeProtectedWritePaths("/work/proj", false);
		expect(without.length).toBe(withSelf.length + 1);
	});
});

describe("shipped examples", () => {
	for (const name of ["full-reference", "gradle-spring-boot"]) {
		test(`${name}.sandbox.jsonc parses with no errors or warnings`, () => {
			const r = parseConfigFile(path.join(import.meta.dirname, "..", "examples", `${name}.sandbox.jsonc`));
			expect(r.error).toBeUndefined();
			expect(r.warnings).toEqual([]);
			expect(r.config).toBeDefined();
		});
	}
});
