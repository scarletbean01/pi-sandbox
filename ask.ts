import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import { segmentBinary } from "./commands";

export type CommandChoice = "once" | "exact" | "prefix" | "deny";
export type PathChoice = "once" | "path" | "subtree" | "deny";
export type ToolChoice = "once" | "exact" | "deny";

const ONCE = "Allow once";
const DENY = "Deny";

/** Ask the user about an unlisted command form. `via` marks proxy-unwrapped commands. */
export async function askCommand(ctx: ExtensionContext, form: string, via?: string): Promise<CommandChoice> {
	const binary = segmentBinary(form);
	const exactLabel = `Always allow "${form}"`;
	const prefixLabel = `Always allow "${binary} *"`;
	const marker = via ? ` (via ${via})` : "";

	const choice = await ctx.ui.select(`Unknown command${marker}:\n\n  ${form}\n\nAllow?`, [
		ONCE,
		exactLabel,
		prefixLabel,
		DENY,
	]);

	if (choice === ONCE) return "once";
	if (choice === exactLabel) return "exact";
	if (choice === prefixLabel) return "prefix";
	return "deny";
}

/** Ask the user about an unlisted custom tool. Exact-name allow only, no prefix option. */
export async function askTool(ctx: ExtensionContext, toolName: string): Promise<ToolChoice> {
	const exactLabel = `Always allow "${toolName}"`;

	const choice = await ctx.ui.select(`Unknown tool:\n\n  ${toolName}\n\nAllow?`, [ONCE, exactLabel, DENY]);

	if (choice === ONCE) return "once";
	if (choice === exactLabel) return "exact";
	return "deny";
}

/** Ask the user about a path outside the allowed folders. */
export async function askPath(ctx: ExtensionContext, normalizedPath: string): Promise<PathChoice> {
	const pathLabel = `Always allow this path`;
	const subtreeLabel = `Always allow "${normalizedPath}/**"`;

	const choice = await ctx.ui.select(`Path outside allowed folders:\n\n  ${normalizedPath}\n\nAllow?`, [
		ONCE,
		pathLabel,
		subtreeLabel,
		DENY,
	]);

	if (choice === ONCE) return "once";
	if (choice === pathLabel) return "path";
	if (choice === subtreeLabel) return "subtree";
	return "deny";
}
