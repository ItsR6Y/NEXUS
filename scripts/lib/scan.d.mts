export const SKIP_DIRS: Set<string>
export const CONTENT_RULES: [string, RegExp][]
export const FILENAME_RULES: [string, RegExp][]
export function scanTree(root: string, opts?: { allow?: RegExp[] }): string[]
