import * as fs from "node:fs";
import * as path from "node:path";
import { homeDir } from "./util";

export interface AuditEntry {
	tool: string;
	verdict: "allow" | "deny" | "ask" | "error";
	kind?: string;
	subject?: string;
	pattern?: string;
	via?: string;
	choice?: string;
	bwrap?: boolean;
	note?: string;
}

const MAX_BYTES = 5 * 1024 * 1024;

export function auditPath(): string {
	return path.join(homeDir(), ".pi", "agent", "sandbox-audit.jsonl");
}

/**
 * Append one JSONL decision record (opt-in via `audit: true` in the global
 * config). Never logs file contents or env values; rotates at 5 MB.
 */
export function writeAudit(entry: AuditEntry, file: string = auditPath()): void {
	try {
		fs.mkdirSync(path.dirname(file), { recursive: true });
		try {
			if (fs.statSync(file).size > MAX_BYTES) fs.renameSync(file, `${file}.1`);
		} catch {
			// no file yet
		}
		const line = JSON.stringify({ ts: new Date().toISOString(), ...entry });
		fs.appendFileSync(file, `${line}\n`, { mode: 0o600 });
	} catch {
		// auditing must never break a tool call
	}
}
