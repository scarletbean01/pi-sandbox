/** Minimal type declarations for picomatch (API surface used by this extension). */
declare module "picomatch" {
	export interface PicomatchOptions {
		dot?: boolean;
		nocase?: boolean;
	}
	export type Matcher = (test: string) => boolean;
	interface Picomatch {
		(pattern: string | string[], options?: PicomatchOptions): Matcher;
		isMatch(str: string, pattern: string | string[], options?: PicomatchOptions): boolean;
	}
	const picomatch: Picomatch;
	export default picomatch;
}
