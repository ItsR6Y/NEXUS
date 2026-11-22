/**
 * @vitest-environment jsdom
 */
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { TerminalPage } from '../../src/renderer/src/pages/Terminal'
import type { Envelope } from '../../src/shared/types'
import { installApi, ok, session, settings } from './harness'

vi.mock('@xterm/xterm', async () => ({ Terminal: (await import('./xterm')).FakeTerminal }))
vi.mock('@xterm/addon-fit', async () => ({ FitAddon: (await import('./xterm')).FakeFitAddon }))
vi.mock('@xterm/addon-search', async () => ({ SearchAddon: (await import('./xterm')).FakeSearchAddon }))

const disconnect = vi.fn<(id: string) => Promise<Envelope<true>>>()

beforeEach(() => {
  disconnect.mockReset()
  disconnect.mockResolvedValue(ok(true))
  installApi({
    sessions: { list: async () => ok([session()]), disconnect },
    settings: { get: async () => ok(settings()) },
    terminal: {
      open: async () => ok(true),
      input: async () => ok(true),
      resize: async () => ok(true),
      close: async () => ok(true)
    },
    commands: { execute: vi.fn(), cancel: vi.fn() }
  })
})

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

describe('Terminal keyboard handling', () => {
  it('binds Ctrl+W to close the selected tab', async () => {
    render(<TerminalPage active focusSession={null} go={() => {}} />)
    await screen.findByTestId('run-command-drawer')

    // Retry inside waitFor: the window listener is (re)registered by an effect, which can land
    // a tick after the first paint under full-suite load.
    await waitFor(() => {
      fireEvent.keyDown(window, { key: 'w', ctrlKey: true })
      expect(disconnect).toHaveBeenCalledWith('s-1')
    }, { timeout: 5000 })
  })

  it('does not re-register the window keydown listener on unrelated re-renders', async () => {
    const go = (): void => {}
    const { rerender } = render(<TerminalPage active focusSession={null} go={go} />)
    await screen.findByTestId('run-command-drawer')

    const spy = vi.spyOn(window, 'addEventListener')
    rerender(<TerminalPage active focusSession={null} go={go} />)
    const keydownAdds = spy.mock.calls.filter(([type]) => type === 'keydown').length
    expect(keydownAdds).toBe(0)
  })
})
