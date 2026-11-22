/**
 * @vitest-environment jsdom
 */
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { Servers } from '../../src/renderer/src/pages/Servers'
import type { Envelope, ServerPrivateInfo } from '../../src/shared/types'
import type { ServerDraftInput } from '../../src/shared/api'
import { installApi, ok, server } from './harness'

const create = vi.fn<(input: ServerDraftInput) => Promise<Envelope<ServerPrivateInfo>>>()

beforeEach(() => {
  create.mockReset()
  create.mockResolvedValue(ok(server()))
  installApi({
    servers: { list: async () => ok([]), create, update: async () => ok(server()), pickKeyPath: async () => ok(null) },
    sessions: { list: async () => ok([]) }
  })
})

afterEach(cleanup)

describe('ServerForm', () => {
  it('keeps Save disabled until the required fields are filled', async () => {
    render(<Servers go={() => {}} />)
    await screen.findByText(/No matching servers/)
    fireEvent.click(screen.getByTestId('add-server'))

    const save = screen.getByTestId('f-save') as HTMLButtonElement
    expect(save.disabled).toBe(true)

    fireEvent.change(screen.getByTestId('f-name'), { target: { value: 'prod' } })
    fireEvent.change(screen.getByTestId('f-host'), { target: { value: '10.0.0.1' } })
    fireEvent.change(screen.getByTestId('f-user'), { target: { value: 'deploy' } })
    expect(save.disabled).toBe(false)
  })

  it('creates a password server with the exact contract payload and closes the dialog', async () => {
    render(<Servers go={() => {}} />)
    await screen.findByText(/No matching servers/)
    fireEvent.click(screen.getByTestId('add-server'))

    fireEvent.change(screen.getByTestId('f-name'), { target: { value: 'prod' } })
    fireEvent.change(screen.getByTestId('f-host'), { target: { value: '10.0.0.1' } })
    fireEvent.change(screen.getByTestId('f-user'), { target: { value: 'deploy' } })
    fireEvent.click(screen.getByTestId('f-save'))

    await waitFor(() => expect(create).toHaveBeenCalledTimes(1))
    expect(create).toHaveBeenCalledWith({
      name: 'prod',
      host: '10.0.0.1',
      port: 22,
      username: 'deploy',
      authType: 'password',
      keyPath: null,
      approvalPolicy: 'ask',
      mcpAccessEnabled: false
    })
    await waitFor(() => expect(screen.queryByTestId('f-name')).toBeNull())
  })

  it('swaps the secret field for a key-path field when key auth is selected', async () => {
    render(<Servers go={() => {}} />)
    await screen.findByText(/No matching servers/)
    fireEvent.click(screen.getByTestId('add-server'))

    expect(screen.getByTestId('f-secret')).toBeTruthy()
    fireEvent.change(screen.getByTestId('f-auth'), { target: { value: 'key' } })

    expect(screen.queryByTestId('f-secret')).toBeNull()
    expect(screen.getByTestId('f-keypath')).toBeTruthy()
  })
})
