// Fails if anything that looks like a real secret is present in the source tree.
import { scanTree } from './lib/scan.mjs'

// Test fixtures and docs intentionally contain fake credentials for redaction tests.
const ALLOW = [/^tests\//, /^docs\//, /^SECURITY\.md$/, /^scripts\/lib\/scan\.mjs$/]
const root = process.argv[2] ?? process.cwd()
const hits = scanTree(root, { allow: ALLOW })
if (hits.length) { console.error('Possible secrets found:\n' + hits.join('\n')); process.exit(1) }
console.log('scan-secrets: clean')
