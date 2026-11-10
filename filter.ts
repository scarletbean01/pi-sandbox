import * as path from "node:path";
import { isDirectory, matchesDeny } from "./paths";
import { expandTilde } from "./util";

export interface TextBlock {
	type: string;
	text?: string;
	[key: string]: unknown;
}

export interface FilterOutcome {
	content: TextBlock[];
	/** Number of result lines removed. */
	hidden: number;
}

const FILTERED_TOOLS = new Set(["grep", "find", "ls"]);

export function isFilteredTool(toolName: string): boolean {
	return FILTERED_TOOLS.has(toolName);
}

/** `src/a.ts:12: text` (match) or `src/a.ts-12- text` (context). */
const GREP_LINE = /^(.+?)(?::|-)(\d+)(?::|-)(?: |$)/;

/**
 * Remove result lines of grep/find/ls whose path matches `paths.deny`.
 * The root `path` argument is checked before the call; this closes the
 * "children of an allowed root" hole (rg --hidden, directory listings).
 * Returns undefined when nothing was hidden.
 */
export function filterListing(
	toolName: string,
	input: Record<string, unknown>,
	content: TextBlock[],
	deny: string[],
	cwd: string,
): FilterOutcome | undefined {
	if (!FILTERED_TOOLS.has(toolName)) return undefined;
	const rawRoot = typeof input.path === "string" && input.path.length > 0 ? input.path : ".";
	const root = path.resolve(cwd, expandTilde(rawRoot));
	// grep over a single file reports the basename.
	const base = isDirectory(root) ? root : path.dirname(root);

	const denied = (rel: string, isDir: boolean): boolean => {
		const abs = path.resolve(base, rel);
		return matchesDeny(abs, deny, cwd) !== undefined || (isDir && matchesDeny(`${abs}/`, deny, cwd) !== undefined);
	};

	let hidden = 0;
	const out: TextBlock[] = [];
	for (const block of content) {
		if (block.type !== "text" || typeof block.text !== "string") {
			out.push(block);
			continue;
		}
		const kept: string[] = [];
		for (const line of block.text.split("\n")) {
			if (line.length === 0 || line.startsWith("[")) {
				kept.push(line);
				continue;
			}
			let drop = false;
			if (toolName === "grep") {
				const m = GREP_LINE.exec(line);
				if (m) drop = denied(m[1], false);
			} else {
				const isDir = line.endsWith("/");
				drop = denied(isDir ? line.slice(0, -1) : line, isDir);
			}
			if (drop) hidden++;
			else kept.push(line);
		}
		out.push({ ...block, text: kept.join("\n") });
	}
	if (hidden === 0) return undefined;
	out.push({ type: "text", text: `[sandbox: ${hidden} results hidden by deny policy]` });
	return { content: out, hidden };
}
