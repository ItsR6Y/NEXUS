/** Minimal xterm stand-ins for jsdom: the real addon needs a canvas/layout engine. */
export class FakeTerminal {
  options: Record<string, unknown> = {}
  cols = 80
  rows = 24
  loadAddon(): void {}
  open(): void {}
  attachCustomKeyEventHandler(): void {}
  onData(): { dispose: () => void } { return { dispose: () => {} } }
  onResize(): { dispose: () => void } { return { dispose: () => {} } }
  write(): void {}
  focus(): void {}
  dispose(): void {}
  paste(): void {}
  hasSelection(): boolean { return false }
  getSelection(): string { return '' }
}

export class FakeFitAddon {
  fit(): void {}
}

export class FakeSearchAddon {
  findNext(): void {}
}
