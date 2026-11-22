import { redactText } from '../security/redaction'

// Strips CSI, OSC, and simple 2-byte ANSI escape sequences.
const ANSI_RE = /(?:\x1B\[[0-?]*[ -/]*[@-~]|\x1B\][^\x07\x1B]*(?:\x07|\x1B\\)|\x1B[@-Z\\-_])/g

export function stripAnsi(text: string): string {
  return text.replace(ANSI_RE, '').replace(/\r\n/g, '\n').replace(/\r/g, '\n')
}

/**
 * Main-process bounded ring buffer storing recent shell output for a session.
 * Read-only tail queries strip ANSI sequences and redact all secrets before returning.
 *
 * Chunks are kept in arrival order and the UTF-8 byte total is tracked incrementally, so appending
 * never re-encodes the whole buffer (Section 8). Trimming drops whole chunks and only
 * re-encodes the leading chunk when the cut must land inside it.
 */
export class TerminalTailBuffer {
  private chunks: string[] = []
  /** UTF-8 byte length of each chunk, parallel to `chunks`. */
  private sizes: number[] = []
  private bytes = 0
  private maxBytes: number

  constructor(maxBytes: number) {
    this.maxBytes = Math.max(4096, maxBytes)
  }

  setMaxBytes(maxBytes: number): void {
    this.maxBytes = Math.max(4096, maxBytes)
    this.trim()
  }

  append(chunk: string): void {
    if (!chunk) return
    const bytes = Buffer.byteLength(chunk, 'utf8')
    this.chunks.push(chunk)
    this.sizes.push(bytes)
    this.bytes += bytes
    this.trim()
  }

  private trim(): void {
    // Drop whole chunks while the remainder still covers the cap: no re-encoding at all.
    while (this.chunks.length > 1 && this.bytes - this.sizes[0] >= this.maxBytes) {
      this.bytes -= this.sizes[0]
      this.chunks.shift()
      this.sizes.shift()
    }
    if (this.bytes <= this.maxBytes) return

    const headBytes = this.sizes[0]
    const head = Buffer.from(this.chunks[0], 'utf8')
    // Bytes to discard from the front of the whole buffer; guaranteed to fall inside the head chunk
    // because whole chunks that could be dropped entirely were already removed above.
    let start = this.bytes - this.maxBytes
    // Never begin on a UTF-8 continuation byte (0b10xxxxxx): advance to the next code-point
    // boundary so a mid-character cut cannot decode into U+FFFD in the tail.
    while (start < headBytes && (head[start] & 0xc0) === 0x80) start++
    if (start >= headBytes) {
      this.bytes -= headBytes
      this.chunks.shift()
      this.sizes.shift()
      return
    }
    this.chunks[0] = head.subarray(start).toString('utf8')
    this.sizes[0] = headBytes - start
    this.bytes = headBytes - start + (this.bytes - headBytes)
  }

  readTail(lines: number, secrets: Iterable<string> = []): string {
    const clean = redactText(stripAnsi(this.chunks.join('')), secrets)
    const allLines = clean.split('\n')
    const capped = Math.max(1, Math.min(200, Math.floor(lines)))
    return allLines.slice(-capped).join('\n')
  }
}
