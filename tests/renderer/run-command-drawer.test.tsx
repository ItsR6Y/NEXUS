/**
 * @vitest-environment jsdom
 */
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { TerminalPage } from '../../src/renderer/src/pages/Terminal'
import type { Envelope, ExecutionResult } from '../../src/shared/types'
import { installApi, ok, session, settings } from './harness'

vi.mock('@xterm/xterm', async () => ({ Terminal: (await import('./xterm')).FakeTerminal }))
vi.mock('@xterm/addon-fit', async () => ({ FitAddon: (await import('./xterm')).FakeFitAddon }))
vi.mock('@xterm/addon-search', async () => ({ SearchAddon: (await import('./xterm')).FakeSearchAddon }))

const execute = vi.fn<(input: { serverId: string; sessionId: string; command: string; clientCommandId?: string }) => Promise<Envelope<ExecutionResult>>>()
const cancel = vi.fn<(commandId: string) => Promise<Envelope<{ cancelled: boolean }>>>()

beforeEach(() => {
  execute.mockReset()
  cancel.mockReset()
  cancel.mockResolvedValue(ok({ cancelled: true }))
  installApi({
    sessions: { list: async () => ok([session()]), disconnect: async () => ok(true) },
    settings: { get: async () => ok(settings()) },
    terminal: {
      open: async () => ok(true),
      input: async () => ok(true),
      resize: async () => ok(true),
      close: async () => ok(true)
    },
    commands: { execute, cancel }
  })
})

afterEach(cleanup)

describe('Run Command drawer (UI half)', () => {
  it('offers Cancel while the command is in flight and cancels by the client command id', async () => {
    // Never settles: mimics an execution still awaiting authorization/SSH.
    execute.mockReturnValue(new Promise<Envelope<ExecutionResult>>(() => {}))

    render(<TerminalPage active focusSession={null} go={() => {}} />)
    await screen.findByTestId('run-command-drawer')

    fireEvent.change(screen.getByTestId('run-cmd-input'), { target: { value: 'uptime' } })
    fireEvent.click(screen.getByTestId('run-cmd-btn'))

    await waitFor(() => expect(execute).toHaveBeenCalledTimes(1))
    const input = execute.mock.calls[0][0]
    expect(input).toMatchObject({ serverId: 'srv-1', sessionId: 's-1', command: 'uptime' })
    expect(typeof input.clientCommandId).toBe('string')

    const cancelBtn = await screen.findByText('Cancel')
    fireEvent.click(cancelBtn)

    await waitFor(() => expect(cancel).toHaveBeenCalledWith(input.clientCommandId))
  })

  it('does not expose Cancel when no command is running', async () => {
    render(<TerminalPage active focusSession={null} go={() => {}} />)
    await screen.findByTestId('run-command-drawer')
    expect(screen.queryByText('Cancel')).toBeNull()
  })
})
