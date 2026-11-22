import { describe, expect, it } from 'vitest'
import { TerminalTailBuffer } from '../../src/main/core/ssh/terminal-tail'

describe('TerminalTailBuffer chunked ring', () => {
  it('keeps at most maxBytes and returns the most recent text', () => {
    const ring = new TerminalTailBuffer(4096)
    for (let i = 0; i < 200; i++) ring.append(`line-${i}\n`)
    const tail = ring.readTail(200)
    expect(Buffer.byteLength(tail, 'utf8')).toBeLessThanOrEqual(4096)
    expect(tail.trimEnd().split('\n').slice(-5)).toEqual([
      'line-195', 'line-196', 'line-197', 'line-198', 'line-199'
    ])
  })

  it('never splits a multibyte character when the cut lands across chunk boundaries', () => {
    const ring = new TerminalTailBuffer(4096)
    for (let i = 0; i < 100; i++) ring.append('\u20ac'.repeat(30))
    const tail = ring.readTail(200)
    expect(tail).not.toContain('\ufffd')
    expect(Buffer.byteLength(tail, 'utf8')).toBeLessThanOrEqual(4096)
    expect(tail.startsWith('\u20ac')).toBe(true)
  })

  it('emits the same tail as an equivalent flat buffer', () => {
    const ring = new TerminalTailBuffer(4096)
    const chunks: string[] = []
    for (let i = 0; i < 300; i++) {
      const c = `chunk ${i} ${'x'.repeat(i % 37)}\n`
      chunks.push(c)
      ring.append(c)
    }
    const flat = chunks.join('')
    let expected = flat
    while (Buffer.byteLength(expected, 'utf8') > 4096) {
      const raw = Buffer.from(expected, 'utf8')
      let start = raw.length - 4096
      while (start < raw.length && (raw[start] & 0xc0) === 0x80) start++
      expected = raw.subarray(start).toString('utf8')
    }
    expect(ring.readTail(200)).toBe(expected.split('\n').slice(-200).join('\n'))
  })

  it('still redacts secrets in the tail', () => {
    const ring = new TerminalTailBuffer(4096)
    ring.append('before\n\u001b[31mcanary-secret\u001b[0m\nafter\n')
    const tail = ring.readTail(10, ['canary-secret'])
    expect(tail).not.toContain('canary-secret')
    expect(tail).toContain('before')
  })

  it('honours a lowered cap after data was buffered', () => {
    const ring = new TerminalTailBuffer(16384)
    ring.append('a'.repeat(12_000))
    ring.append('b'.repeat(3_000))
    ring.setMaxBytes(4096)
    expect(Buffer.byteLength(ring.readTail(1), 'utf8')).toBeLessThanOrEqual(4096)
  })
})
