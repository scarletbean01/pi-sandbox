import { expect, test } from "bun:test";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { writeAudit } from "../audit";

test("audit lines are JSONL with a timestamp and rotate at 5 MB", () => {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pi-sbx-audit-"));
	const file = path.join(dir, "sandbox-audit.jsonl");
	writeAudit({ tool: "bash", verdict: "deny", kind: "command", subject: "sudo id", pattern: "sudo *" }, file);
	const line = JSON.parse(fs.readFileSync(file, "utf8").trim());
	expect(line.tool).toBe("bash");
	expect(line.verdict).toBe("deny");
	expect(typeof line.ts).toBe("string");
	fs.writeFileSync(file, "x".repeat(5 * 1024 * 1024 + 10));
	writeAudit({ tool: "read", verdict: "allow" }, file);
	expect(fs.existsSync(`${file}.1`)).toBe(true);
	expect(fs.readFileSync(file, "utf8").trim().split("\n").length).toBe(1);
	fs.rmSync(dir, { recursive: true, force: true });
});
