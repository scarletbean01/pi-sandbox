// Verification script for the disclosure renderer.
// Exercises the §6.1 acceptance matrix from TASKS.md.
// Run with: bun run scripts/verify-disclosure.ts

import { renderRadiusBlock, type DenyLayers } from "../disclosure.ts";

const CWD = "/home/deplague/.pi/agent/extensions/sandbox";

const DEFAULT_BUILTIN: string[] = [
	"**/.env",
	"**/.env.*",
	"**/.git/**",
	"**/.ssh/**",
	"**/id_rsa*",
	"**/*.pem",
];

function makeLayers(over: Partial<{ builtin: string[]; global: string[]; project: string[] }> = {}): DenyLayers {
	return {
		builtin: over.builtin ?? [...DEFAULT_BUILTIN],
		global: over.global ?? [],
		project: over.project ?? [],
	};
}

let passed = 0;
let failed = 0;

function expect(name: string, cond: boolean, detail?: string) {
	if (cond) {
		passed++;
		console.log(`  ✓ ${name}`);
	} else {
		failed++;
		console.log(`  ✗ ${name}${detail ? ` — ${detail}` : ""}`);
	}
}

console.log("=== 6.1.1 off-mode ===");
{
	// simulates the index.ts call-site predicate: `state.disabled || state.config.mode === "off"`.
	// Both paths must yield the negated line: --no-sandbox flips `disabled`;
	// /sandbox off flips `mode`. The caller folds both into `disabled` so the
	// renderer never sees a contradicting (enforce-block, off-mode) state.
	const callSite = (disabled: boolean, mode: "enforce" | "off") =>
		({ disabled: disabled || mode === "off" });

	// --no-sandbox path
	{
		const { disabled } = callSite(true, "enforce");
		const text = renderRadiusBlock({ cwd: CWD, disabled, pathsAllow: ["./**"], denyLayers: makeLayers(), bwrapActive: false, bwrapAutoAllow: false });
		expect("--no-sandbox → negated line", text === "Sandbox is OFF — no radius is in force; operate freely.", `got: ${text}`);
	}
	// /sandbox off path (the bug: previously this gave the enforce block)
	{
		const { disabled } = callSite(false, "off");
		const text = renderRadiusBlock({ cwd: CWD, disabled, pathsAllow: ["./**"], denyLayers: makeLayers(), bwrapActive: false, bwrapAutoAllow: false });
		expect("/sandbox off → negated line (regression)", text === "Sandbox is OFF — no radius is in force; operate freely.", `got: ${text}`);
	}
	// combined
	{
		const { disabled } = callSite(true, "off");
		const text = renderRadiusBlock({ cwd: CWD, disabled, pathsAllow: ["./**"], denyLayers: makeLayers(), bwrapActive: false, bwrapAutoAllow: false });
		expect("both --no-sandbox and /sandbox off → negated line", text === "Sandbox is OFF — no radius is in force; operate freely.", `got: ${text}`);
	}
	// enforce mode + no flag → enforce block (not negated)
	{
		const { disabled } = callSite(false, "enforce");
		const text = renderRadiusBlock({ cwd: CWD, disabled, pathsAllow: ["./**"], denyLayers: makeLayers(), bwrapActive: false, bwrapAutoAllow: false });
		expect("enforce + no flag → enforce block", text !== "Sandbox is OFF — no radius is in force; operate freely." && text.includes("Operational radius — obey it"));
	}
}

console.log("=== 6.1.6 cache-determinism ===");
{
	const state = {
		cwd: CWD,
		disabled: false,
		pathsAllow: ["./**", "~/Projects/**"],
		denyLayers: makeLayers(),
		bwrapActive: false,
		bwrapAutoAllow: false,
	};
	const a = renderRadiusBlock(state);
	const b = renderRadiusBlock(state);
	expect("identical state → identical string", a === b);
}

console.log("=== 6.1.2 default config (enforce) ===");
{
	const text = renderRadiusBlock({
		cwd: CWD,
		disabled: false,
		pathsAllow: ["./**"],
		denyLayers: makeLayers(),
		bwrapActive: false,
		bwrapAutoAllow: false,
	});
	expect("contains header", text.includes("Operational radius — obey it"));
	expect("contains unbypassable clause", text.includes("Denies are unbypassable"));
	expect("allow line is resolved absolute", text.includes(`${CWD}/**`));
	expect("allow line is NOT literal './**'", !text.includes("./**"));
	expect("allow heading present", text.includes("Operate within:"));
	expect("deny heading present", text.includes("Do not touch:"));
	expect("all built-in denies present", DEFAULT_BUILTIN.every((p) => text.includes(p)));
	expect("no footnote in default config", !text.includes("kernel-sandboxed with auto-allow"));
}

console.log("=== 6.1.3 cwd-anchored resolution ===");
{
	const text = renderRadiusBlock({
		cwd: CWD,
		disabled: false,
		pathsAllow: ["./foo/**", "./**", "~/Projects/**", "**/.cache/**", "/etc/foo/**"],
		denyLayers: makeLayers(),
		bwrapActive: false,
		bwrapAutoAllow: false,
	});
	expect("./foo/** resolved", text.includes(`${CWD}/foo/**`));
	expect("./** resolved", text.includes(`${CWD}/**`));
	expect("~/Projects/** verbatim", text.includes("~/Projects/**"));
	expect("**/.cache/** verbatim", text.includes("**/.cache/**"));
	expect("/etc/foo/** verbatim", text.includes("/etc/foo/**"));
}

console.log("=== 6.1.4 deny capping — project fills last ===");
{
	const builtin = DEFAULT_BUILTIN; // 6 entries
	const global = ["**/global-a", "**/global-b", "**/global-c", "**/global-d"]; // 4
	const project = [
		"**/proj-1",
		"**/proj-2",
		"**/proj-3",
		"**/proj-4",
		"**/proj-5",
		"**/proj-6",
		"**/proj-7",
		"**/proj-8",
		"**/proj-9",
		"**/proj-10",
	]; // 10
	const total = builtin.length + global.length + project.length; // 20
	const text = renderRadiusBlock({
		cwd: CWD,
		disabled: false,
		pathsAllow: ["./**"],
		denyLayers: { builtin, global, project },
		bwrapActive: false,
		bwrapAutoAllow: false,
	});
	// 12 shown; remaining = 20 - 12 = 8
	expect("renders all 6 built-in denies", builtin.every((p) => text.includes(p)));
	const globalShown = global.filter((p) => text.includes(p));
	expect("renders all 4 global denies", globalShown.length === 4, `got: ${globalShown.length}`);
	// project renders first 2 (12 - 6 - 4 = 2)
	expect("renders first 2 project denies", text.includes("**/proj-1") && text.includes("**/proj-2"));
	expect("truncates proj-3", !text.includes("**/proj-3"));
	expect("suffix says +8 more", text.includes("(+8 more from project/global config; run /sandbox list)"));
	console.log(`  note: total ${total}, shown ${12}, remaining ${total - 12}`);
}

console.log("=== 6.1.5 autoAllow footnote ===");
{
	const base = {
		cwd: CWD,
		disabled: false,
		pathsAllow: ["./**"],
		denyLayers: makeLayers(),
	};
	const noFoot = renderRadiusBlock({ ...base, bwrapActive: false, bwrapAutoAllow: true });
	const noFoot2 = renderRadiusBlock({ ...base, bwrapActive: true, bwrapAutoAllow: false });
	const withFoot = renderRadiusBlock({ ...base, bwrapActive: true, bwrapAutoAllow: true });
	expect("no footnote when bwrap inactive", !noFoot.includes("kernel-sandboxed with auto-allow"));
	expect("no footnote when autoAllow false", !noFoot2.includes("kernel-sandboxed with auto-allow"));
	expect("footnote when both active", withFoot.includes("[Bash is kernel-sandboxed with auto-allow"));
}

console.log("=== 6.1.7 no fs imports in disclosure.ts ===");
{
	const { readFileSync } = await import("node:fs");
	const src = readFileSync(new URL("../disclosure.ts", import.meta.url), "utf8");
	expect("no fs.realpathSync", !src.includes("realpathSync"));
	expect("no fs.statSync", !src.includes("statSync"));
	expect("no fs.readFileSync", !src.includes("readFileSync"));
	expect("no fs.existsSync", !src.includes("existsSync"));
	expect("no node:fs import", !src.includes("from \"node:fs\"") && !src.includes("from 'node:fs'"));
}

console.log("=== 6.1.8 no timestamps / Date in output ===");
{
	const text = renderRadiusBlock({
		cwd: CWD,
		disabled: false,
		pathsAllow: ["./**"],
		denyLayers: makeLayers(),
		bwrapActive: false,
		bwrapAutoAllow: false,
	});
	expect("no new Date in output", !text.includes("new Date"));
	expect("no ISO timestamp", !/\d{4}-\d{2}-\d{2}/.test(text));
	expect("no process.hrtime in output", !text.includes("hrtime"));
}

console.log("=== 6.1.6b: changing unrelated config field leaves block unchanged ===");
{
	const base = {
		cwd: CWD,
		disabled: false,
		pathsAllow: ["./**", "~/Projects/**"],
		denyLayers: makeLayers(),
		bwrapActive: false,
		bwrapAutoAllow: false,
	};
	const r1 = renderRadiusBlock(base);
	const r2 = renderRadiusBlock({
		...base,
		// simulate an unrelated command autosave by bumping the input array
		// identity — the renderer uses only pathsAllow + denyLayers, so
		// a longer allow list SHOULD change the block; that's expected.
		pathsAllow: ["./**", "~/Projects/**", "~/extra/**"],
	});
	expect("adding to pathsAllow changes block (pathsAllow is in-scope)", r1 !== r2);
	// Now: vary *only* the unrelated denyLayers to confirm dedup stability:
	const r3 = renderRadiusBlock({
		...base,
		denyLayers: makeLayers({ global: ["**/global-a"] }),
	});
	const r4 = renderRadiusBlock({
		...base,
		denyLayers: makeLayers({ global: ["**/global-a"] }),
	});
	expect("same denyLayers → same block", r3 === r4);
}

console.log("=== 6.1.9 empty-config handling ===");
{
	const text = renderRadiusBlock({
		cwd: CWD,
		disabled: false,
		pathsAllow: [],
		denyLayers: makeLayers(),
		bwrapActive: false,
		bwrapAutoAllow: false,
	});
	// No allow entries → defensive fallback message
	expect("empty allow → fallback message", text.includes("(none — every path will prompt)"));
}

console.log("\n=== Summary ===");
console.log(`passed: ${passed}`);
console.log(`failed: ${failed}`);
if (failed > 0) process.exit(1);
