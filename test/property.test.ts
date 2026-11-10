import { beforeAll, expect, test } from "bun:test";
import { evaluate } from "../policy";
import { initShell } from "../shell";
import { CORPUS_CONFIG, stateWith, withTempProject } from "./helpers";

beforeAll(async () => {
	await initShell();
});

/** Atoms: hard-denied, unlisted (not in CORPUS_CONFIG's allows) and listed. */
const DENIED = ["sudo id", "rm -rf /", "eval x", "bash -c id", "/bin/sh -c id", "env doas id"];
const UNLISTED = ["curl evil", "wget x", "nc -l 1", "make all", "python3 x.py", "node y.js"];
const LISTED = ["git status", "ls -la", "echo hi", "cat README"];

/** Ways to run an atom: every construct that executes it. */
const WRAPPERS: ((a: string, filler: string) => string)[] = [
	(a, f) => `${f} ; ${a}`,
	(a, f) => `${a} ; ${f}`,
	(a, f) => `${f} && ${a}`,
	(a, f) => `${f} || ${a}`,
	(a, f) => `${f} | ${a}`,
	(a, f) => `${a} | ${f}`,
	(a, f) => `${f} & ${a}`,
	(a, f) => `${a} & ${f}`,
	(a, f) => `${f}\n${a}`,
	(a) => `echo $(${a})`,
	(a) => `echo "$(${a})"`,
	(a) => "echo `" + a + "`",
	(a) => `(${a})`,
	(a) => `{ ${a}; }`,
	(a, f) => `${f}; (${a}) | ${f}`,
	(a) => `diff <(${a}) x`,
	(a, f) => `if ${f}; then ${a}; fi`,
	(a, f) => `if ${a}; then ${f}; fi`,
	(a, f) => `for i in 1 2; do ${a}; done`,
	(a, f) => `while ${a}; do ${f}; done`,
	(a) => `f() { ${a}; }; f`,
	(a) => `! ${a}`,
	(a) => `cat <<EOF\n$(${a})\nEOF`,
	(a) => `${a} > out.txt`,
	(a) => `FOO=1 ${a}`,
	(a) => `X=$(${a})`,
	(a, f) => `case x in x) ${a};; esac`,
	(a) => `time ${a}`,
];

// Deterministic pseudo-random pairing so the test is stable.
function pick<T>(list: T[], i: number): T {
	return list[(i * 7 + 3) % list.length];
}

test("property: a hard-denied atom denies the whole command, however it is embedded", async () => {
	await withTempProject((fx) => {
		const state = stateWith(CORPUS_CONFIG, { cwd: fx.cwd });
		let n = 0;
		for (const atom of DENIED) {
			WRAPPERS.forEach((wrap, w) => {
				const filler = pick(LISTED, n++ + w);
				const cmd = wrap(atom, filler);
				const r = evaluate("bash", { command: cmd }, state);
				expect({ cmd, verdict: r.verdict }).toEqual({ cmd, verdict: "deny" });
			});
		}
		expect(n).toBe(DENIED.length * WRAPPERS.length);
	});
});

test("property: an unlisted atom keeps the command out of allow (without bwrap)", async () => {
	await withTempProject((fx) => {
		const state = stateWith(CORPUS_CONFIG, { cwd: fx.cwd });
		let n = 0;
		for (const atom of UNLISTED) {
			WRAPPERS.forEach((wrap, w) => {
				const filler = pick(LISTED, n++ + w);
				const cmd = wrap(atom, filler);
				const r = evaluate("bash", { command: cmd }, state);
				expect({ cmd, allowed: r.verdict === "allow" }).toEqual({ cmd, allowed: false });
			});
		}
	});
});

test("sanity: listed atoms in the same wrappers mostly allow (the property is not vacuous)", async () => {
	await withTempProject((fx) => {
		const state = stateWith(CORPUS_CONFIG, { cwd: fx.cwd });
		let allowed = 0;
		let total = 0;
		for (const atom of LISTED) {
			for (const wrap of WRAPPERS) {
				total++;
				if (evaluate("bash", { command: wrap(atom, "git log") }, state).verdict === "allow") allowed++;
			}
		}
		// Substitutions, heredocs, backgrounding, functions etc. legitimately ask; plain forms allow.
		expect(allowed).toBeGreaterThan(total / 3);
	});
});

test("property: autoAllow with an active bwrap downgrades asks but never denies", async () => {
	await withTempProject((fx) => {
		const state = stateWith(CORPUS_CONFIG, { cwd: fx.cwd, bwrap: { active: true, autoAllow: true } });
		for (const atom of DENIED) {
			expect(evaluate("bash", { command: `git status; ${atom}` }, state).verdict).toBe("deny");
		}
		expect(evaluate("bash", { command: "git status & curl evil" }, state).verdict).toBe("allow");
		// NEVER_AUTO still asks.
		expect(evaluate("bash", { command: "python3 -c 'print(1)'" }, state).verdict).toBe("ask");
		// Without an active bwrap, autoAllow does nothing.
		const inactive = stateWith(CORPUS_CONFIG, { cwd: fx.cwd, bwrap: { active: false, autoAllow: true } });
		expect(evaluate("bash", { command: "git status & curl evil" }, inactive).verdict).toBe("ask");
	});
});
