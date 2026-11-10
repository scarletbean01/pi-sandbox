import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

/** The user's home directory: `$HOME` first (as Node does), then the OS lookup (Bun ignores later HOME changes). */
export function homeDir(): string {
	const fromEnv = process.env.HOME;
	return fromEnv && path.isAbsolute(fromEnv) ? fromEnv : os.homedir();
}

/** Expand a leading `~` / `~/` to the user's home directory. */
export function expandTilde(p: string): string {
	if (p === "~") return homeDir();
	if (p.startsWith("~/")) return path.join(homeDir(), p.slice(2));
	return p;
}

/** Shell single-quote escaping: ' → '\'' */
export function shq(value: string): string {
	return `'${value.replace(/'/g, `'\\''`)}'`;
}

let cachedExtensionDir: string | undefined;

/**
 * Directory holding this extension's source. pi loads extensions through jiti,
 * which turns every module into a `data:` URL, so `import.meta.dirname`/`url`
 * are useless there; jiti does provide a correct CommonJS-style `__dirname`.
 * Candidates are validated by looking for this extension's own files.
 */
export function extensionDir(): string {
	if (cachedExtensionDir) return cachedExtensionDir;
	const meta = import.meta as { dirname?: string; url?: string };
	const candidates: string[] = [];
	if (typeof __dirname !== "undefined") candidates.push(__dirname);
	if (typeof meta.dirname === "string") candidates.push(meta.dirname);
	if (typeof meta.url === "string" && meta.url.startsWith("file:")) candidates.push(path.dirname(fileURLToPath(meta.url)));
	candidates.push(path.join(homeDir(), ".pi", "agent", "extensions", "sandbox"));
	for (const c of candidates) {
		if (path.isAbsolute(c) && fs.existsSync(path.join(c, "shell.ts"))) {
			cachedExtensionDir = c;
			return c;
		}
	}
	return candidates.find((c) => path.isAbsolute(c)) ?? process.cwd();
}

/** Escape glob metacharacters so a literal path persists as exactly that path. */
export function escapeGlob(literal: string): string {
	return literal.replace(/[*?[\]{}()!+\\]/g, "\\$&");
}

/**
 * Small async mutex: `run` calls execute one at a time, in order. Used to
 * serialize ask dialogs and config writes.
 */
export class Mutex {
	private tail: Promise<unknown> = Promise.resolve();
	run<T>(fn: () => Promise<T>): Promise<T> {
		const next = this.tail.then(fn, fn);
		this.tail = next.catch(() => undefined);
		return next;
	}
}
