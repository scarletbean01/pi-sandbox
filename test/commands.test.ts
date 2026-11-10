import { describe, expect, test } from "bun:test";
import {
	canonicalArgv,
	checkArgv,
	commandGlobToRegex,
	denyForms,
	isNeverAuto,
	unwrapProxies,
	unwrapProxyArgv,
} from "../commands";
import { HARD_COMMAND_DENIES, NEVER_AUTO_COMMANDS } from "../config";

describe("commandGlobToRegex", () => {
	test("a trailing ' *' also matches the bare command", () => {
		const re = commandGlobToRegex("git push *");
		expect(re.test("git push")).toBe(true);
		expect(re.test("git push origin main")).toBe(true);
		expect(re.test("git pushx")).toBe(false);
	});
	test("* crosses slashes and newlines", () => {
		expect(commandGlobToRegex("rm -rf *").test("rm -rf /tmp/x")).toBe(true);
		expect(commandGlobToRegex("git commit *").test("git commit -m 'a\nb'")).toBe(true);
	});
	test("regex metacharacters are escaped", () => {
		expect(commandGlobToRegex("echo a.b").test("echo axb")).toBe(false);
		expect(commandGlobToRegex("echo (x)").test("echo (x)")).toBe(true);
	});
});

describe("proxy unwrapping", () => {
	test("string forms from full segment to innermost", () => {
		expect(unwrapProxies("rtk git status", ["rtk"]).forms).toEqual(["rtk git status", "git status"]);
		expect(unwrapProxies("rtk git status", ["rtk"]).via).toBe("rtk");
		expect(unwrapProxies("git status", ["rtk"]).forms).toEqual(["git status"]);
	});
	test("argv forms and depth cap", () => {
		expect(unwrapProxyArgv(["rtk", "rtk", "rtk", "rtk", "ls"], ["rtk"]).forms.length).toBe(4);
	});
	const policy = { allow: ["git status *", "rtk gain"], deny: ["git push *"], proxies: ["rtk"] };
	test("deny on any form", () => {
		expect(checkArgv(["rtk", "git", "push"], true, policy).verdict).toBe("deny");
		expect(checkArgv(["git", "push"], true, policy).verdict).toBe("deny");
	});
	test("allow on any form", () => {
		expect(checkArgv(["rtk", "git", "status"], true, policy).verdict).toBe("allow");
		expect(checkArgv(["rtk", "gain"], true, policy).verdict).toBe("allow");
	});
	test("non-literal never allows", () => {
		expect(checkArgv(["git", "status"], false, policy).verdict).toBe("ask");
	});
});

describe("canonicalization", () => {
	const deny = (argv: string[]) => checkArgv(argv, true, { allow: [], deny: HARD_COMMAND_DENIES, proxies: [] }).verdict;
	test("wrappers are stripped for deny matching", () => {
		expect(canonicalArgv(["env", "-i", "FOO=1", "/usr/bin/sudo", "id"])).toEqual(["sudo", "id"]);
		expect(canonicalArgv(["nice", "-n", "5", "timeout", "10", "ls"])).toEqual(["ls"]);
		expect(canonicalArgv(["stdbuf", "-oL", "cat", "x"])).toEqual(["cat", "x"]);
	});
	test("hard denies match every disguise", () => {
		for (const c of ["bash -c id", "/bin/bash -c id", "bash -xc id", "env -u X sh -c id", "rm -fr /", "rm -Rf /", "setsid sudo id", "ionice -c 3 doas id", "zsh -c id", "busybox sh x"]) {
			expect(deny(c.split(" "))).toBe("deny");
		}
	});
	test("benign commands are not hard-denied", () => {
		for (const c of ["rm -rf build", "bash script.sh", "ls -la", "git rm -rf dir", "dd if=a of=b"]) {
			expect(deny(c.split(" "))).not.toBe("deny");
		}
	});
	test("allow matching stays on the raw form", () => {
		const policy = { allow: ["git *"], deny: [], proxies: [] };
		expect(checkArgv(["/tmp/evil/git", "status"], true, policy).verdict).toBe("ask");
		expect(checkArgv(["env", "git", "status"], true, policy).verdict).toBe("ask");
		expect(checkArgv(["git", "status"], true, policy).verdict).toBe("allow");
	});
	test("denyForms includes proxy-unwrapped and wrapper-stripped variants", () => {
		const forms = denyForms(["rtk", "env", "FOO=1", "sudo", "id"], ["rtk"]);
		expect(forms).toContain("sudo id");
	});
});

describe("NEVER_AUTO", () => {
	const never = (c: string) => isNeverAuto(c.split(" "), NEVER_AUTO_COMMANDS, []);
	test("interpreter one-liners and exec amplifiers", () => {
		for (const c of ["python3 -c x", "python3.12 -c x", "node -e x", "perl -e x", "ruby -e x", "bun -e x", "deno eval x", "xargs rm", "find . -exec rm {} ;", "find . -delete", "git -c core.pager=x log", "env python3 -c x"]) {
			expect(never(c)).toBe(true);
		}
	});
	test("ordinary use is not", () => {
		for (const c of ["python3 script.py", "node index.js", "find . -name x", "git log"]) expect(never(c)).toBe(false);
	});
});
