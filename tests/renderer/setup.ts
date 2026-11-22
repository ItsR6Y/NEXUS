/** jsdom shims for the renderer component harness. No-ops outside jsdom. */
if (typeof window !== 'undefined') {
  if (!('ResizeObserver' in window)) {
    class NoopResizeObserver {
      observe(): void {}
      unobserve(): void {}
      disconnect(): void {}
    }
    ;(window as unknown as { ResizeObserver: unknown }).ResizeObserver = NoopResizeObserver
  }

  const c = window.crypto as Crypto & { randomUUID?: () => string }
  if (typeof c.randomUUID !== 'function') {
    Object.defineProperty(c, 'randomUUID', {
      configurable: true,
      value: (): string => {
        const b = new Uint8Array(16)
        c.getRandomValues(b)
        b[6] = (b[6] & 0x0f) | 0x40
        b[8] = (b[8] & 0x3f) | 0x80
        const h = [...b].map((x) => x.toString(16).padStart(2, '0')).join('')
        return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`
      }
    })
  }
}
