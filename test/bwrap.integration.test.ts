import { afterAll, describe, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import {
	buildBwrapCommand,
	cleanupSessionTmp,
	ensureSessionTmp,
	probeBwrap,
	resetBwrapProbe,
	scanProjectMasks,
	type BwrapExtras,
} from "../bwrap";
import { DEFAULT_CONFIG, mergeConfigs } from "../config";
import { withTempProject } from "./helpers";

const cfg = mergeConfigs(undefined, undefined).bwrap;
const env = { ...process.env, SSH_AUTH_SOCK: "/tmp/agent.sock", DBUS_SESSION_BUS_ADDRESS: "unix:path=/x", TMUX: "/tmp/tmux-1/default,1,0", MY_SERVICE_TOKEN: "t0ken", HERDR_ENV: "1" };

resetBwrapProbe();
const probeFixture = (() => {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pi-sbx-probe-"));
	const probe = probeBwrap({ cfg, cwd: dir, env, extras: { sessionTmp: ensureSessionTmp() } });
	fs.rmSync(dir, { recursive: true, force: true });
	return probe;
})();
const usable = probeFixture.available;

afterAll(() => cleanupSessionTmp());

describe("buildBwrapCommand (no bwrap needed)", () => {
	test("hardening flags and mounts are present", async () => {
		await withTempProject((fx) => {
			const cmd = buildBwrapCommand("echo hi", { ...cfg, network: "off", allowSockets: [] }, fx.cwd, env, { sessionTmp: "/tmp", disableUserns: true });
			for (const flag of ["--cap-drop ALL", "--unshare-cgroup-try", "--disable-userns", "--unshare-net", "--setenv TMPDIR /tmp", "--new-session", "--die-with-parent"]) {
				expect(cmd).toContain(flag);
			}
			// read-only subpaths exist in the fixture (.git/hooks, .pi) and are ro-bound after the cwd bind
			const cwdBind = cmd.indexOf(`--bind '${fx.cwd}' '${fx.cwd}'`);
			const hooks = cmd.indexOf(`--ro-bind '${fx.cwd}/.git/hooks'`);
			expect(cwdBind).toBeGreaterThan(-1);
			expect(hooks).toBeGreaterThan(cwdBind);
			expect(cmd).toContain(`--ro-bind '${fx.cwd}/.pi'`);
			// missing read-only paths are skipped (no stray mount points on the host)
			expect(cmd).not.toContain(".envrc");
			expect(cmd).not.toContain("/.husky");
		});
	});
	test("env: masked and socket-pointing variables are unset, harmless ones are not", async () => {
		await withTempProject((fx) => {
			const cmd = buildBwrapCommand("true", cfg, fx.cwd, env);
			for (const name of ["SSH_AUTH_SOCK", "DBUS_SESSION_BUS_ADDRESS", "TMUX", "MY_SERVICE_TOKEN", "HERDR_ENV"]) {
				expect(cmd).toContain(`--unsetenv '${name}'`);
			}
			expect(cmd).not.toContain("--unsetenv 'PATH'");
		});
	});
	test("without a session tmp, /tmp is an empty tmpfs", async () => {
		await withTempProject((fx) => {
			expect(buildBwrapCommand("true", cfg, fx.cwd, {})).toContain("--tmpfs /tmp");
		});
	});
	test("allowSockets are re-bound after the masks", async () => {
		await withTempProject((fx) => {
			const sock = path.join(fx.outside, "docker.sock");
			fs.writeFileSync(sock, "");
			const cmd = buildBwrapCommand("true", { ...cfg, allowSockets: [sock] }, fx.cwd, {});
			expect(cmd).toContain(`--bind '${sock}' '${sock}'`);
		});
	});
	test("default lists cover credentials and token env patterns", () => {
		expect(DEFAULT_CONFIG.bwrap.denyRead).toEqual(expect.arrayContaining(["~/.config/gh", "~/.git-credentials", "~/.netrc", "~/.npmrc", "~/.config/gcloud", "~/.password-store"]));
		expect(DEFAULT_CONFIG.bwrap.maskEnv).toEqual(expect.arrayContaining(["*TOKEN*", "*PASSWORD*", "*_KEY", "*CREDENTIAL*", "ANTHROPIC_*", "OPENAI_*"]));
	});
});

describe("project masks (H4.3)", () => {
	test("files and dirs matching paths.deny are found; node_modules and .git are skipped", async () => {
		await withTempProject((fx) => {
			fs.mkdirSync(path.join(fx.cwd, "deep", "er"), { recursive: true });
			fs.writeFileSync(path.join(fx.cwd, "deep", "er", ".env.local"), "x");
			fs.mkdirSync(path.join(fx.cwd, "node_modules", "p"), { recursive: true });
			fs.writeFileSync(path.join(fx.cwd, "node_modules", "p", "key.pem"), "x");
			fs.mkdirSync(path.join(fx.cwd, "cfg", ".ssh"), { recursive: true });
			const { masks, capped } = scanProjectMasks(fx.cwd, DEFAULT_CONFIG.paths.deny);
			const rel = masks.map((m) => `${path.relative(fx.cwd, m.path)}${m.dir ? "/" : ""}`).sort();
			expect(rel).toEqual([".env", "cfg/.ssh/", "deep/er/.env.local", "server.pem"]);
			expect(capped).toBe(false);
		});
	});
	test("the scan is capped", async () => {
		await withTempProject((fx) => {
			for (let i = 0; i < 230; i++) fs.writeFileSync(path.join(fx.cwd, `k${i}.pem`), "x");
			const { masks, capped } = scanProjectMasks(fx.cwd, DEFAULT_CONFIG.paths.deny);
			expect(capped).toBe(true);
			expect(masks.length).toBe(200);
		});
	});
});

describe.skipIf(!usable)("inside the wrapped shell (needs working bwrap)", () => {
	function run(cwd: string, command: string, extra: Partial<typeof cfg> = {}, extras: BwrapExtras = {}) {
		const masks = scanProjectMasks(cwd, DEFAULT_CONFIG.paths.deny).masks;
		const wrapped = buildBwrapCommand(command, { ...cfg, ...extra }, cwd, env, { sessionTmp: ensureSessionTmp(), projectMasks: masks, disableUserns: probeFixture.disableUserns, ...extras });
		const r = spawnSync("sh", ["-c", wrapped], { cwd, encoding: "utf8" });
		return { out: r.stdout, err: r.stderr, status: r.status };
	}
	const uid = process.getuid?.() ?? 1000;

	test("the host user bus is hidden (F13)", async () => {
		await withTempProject((fx) => {
			expect(run(fx.cwd, `test -S /run/user/${uid}/bus && echo BUS || echo nobus`).out.trim()).toBe("nobus");
			expect(run(fx.cwd, `ls -A /run/user/${uid} 2>/dev/null | wc -l`).out.trim()).toBe("0");
		});
	});
	test("/tmp is private and empty at the start of a session", async () => {
		await withTempProject((fx) => {
			fs.writeFileSync(path.join(os.tmpdir(), "pi-sbx-host-marker"), "x");
			try {
				const r = run(fx.cwd, "ls -A /tmp | grep -c pi-sbx-host-marker; echo done > /tmp/ok && cat /tmp/ok");
				expect(r.out).toContain("0");
				expect(r.out).toContain("done");
			} finally {
				fs.rmSync(path.join(os.tmpdir(), "pi-sbx-host-marker"), { force: true });
			}
		});
	});
	test("git hooks and config are read-only inside the writable cwd (F14)", async () => {
		await withTempProject((fx) => {
			fs.writeFileSync(path.join(fx.cwd, ".git", "config"), "");
			expect(run(fx.cwd, "touch .git/hooks/pre-commit").status).not.toBe(0);
			expect(run(fx.cwd, "echo x > .git/config").status).not.toBe(0);
			expect(run(fx.cwd, "touch .pi/evil").status).not.toBe(0);
			expect(fs.existsSync(path.join(fx.cwd, ".git", "hooks", "pre-commit"))).toBe(false);
		});
	});
	test("in-project secrets read empty", async () => {
		await withTempProject((fx) => {
			expect(run(fx.cwd, "cat .env 2>/dev/null | wc -c").out.trim()).toBe("0");
			expect(run(fx.cwd, "cat server.pem 2>/dev/null | wc -c").out.trim()).toBe("0");
			expect(fs.readFileSync(path.join(fx.cwd, ".env"), "utf8")).toContain("SECRET=1");
		});
	});
	test("socket env vars and token env vars are gone; TMPDIR points at the private /tmp", async () => {
		await withTempProject((fx) => {
			const r = run(fx.cwd, 'echo "[$SSH_AUTH_SOCK][$DBUS_SESSION_BUS_ADDRESS][$TMUX][$MY_SERVICE_TOKEN][$HERDR_ENV][$TMPDIR]"');
			expect(r.out.trim()).toBe("[][][][][][/tmp]");
		});
	});
	test("writes into cwd and into allowWrite still succeed", async () => {
		await withTempProject((fx) => {
			const extra = path.join(fx.outside, "cache");
			fs.mkdirSync(extra);
			const r = run(fx.cwd, `echo a > ok.txt && echo b > ${extra}/ok.txt && cat ok.txt ${extra}/ok.txt`, { allowWrite: [extra] });
			expect(r.out.trim()).toBe("a\nb");
			expect(fs.readFileSync(path.join(fx.cwd, "ok.txt"), "utf8")).toBe("a\n");
			expect(fs.readFileSync(path.join(extra, "ok.txt"), "utf8")).toBe("b\n");
		});
	});
	test("writes outside cwd and allowWrite fail", async () => {
		await withTempProject((fx) => {
			expect(run(fx.cwd, `echo x > ${fx.outside}/nope`).status).not.toBe(0);
		});
	});
	test("network off isolates the network namespace", async () => {
		await withTempProject((fx) => {
			const r = run(fx.cwd, "cat /proc/net/dev | tail -n +3 | grep -vc '^ *lo:' || true", { network: "off" });
			expect(r.out.trim()).toBe("0");
		});
	});
	test("credentials dirs are hidden", async () => {
		await withTempProject((fx) => {
			const fakeHome = path.join(fx.outside, "home");
			fs.mkdirSync(path.join(fakeHome, ".ssh"), { recursive: true });
			fs.writeFileSync(path.join(fakeHome, ".ssh", "id_ed25519"), "PRIVATE");
			const r = run(fx.cwd, `cat ${fakeHome}/.ssh/id_ed25519 2>/dev/null | wc -c`, { denyRead: [path.join(fakeHome, ".ssh")] });
			expect(r.out.trim()).toBe("0");
		});
	});
});
