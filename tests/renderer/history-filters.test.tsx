/**
 * @vitest-environment jsdom
 */
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { History } from '../../src/renderer/src/pages/History'
import type { Envelope, ExecutionDTO, ExecutionFilter } from '../../src/shared/types'
import { installApi, ok, server } from './harness'

const list = vi.fn<(filter: ExecutionFilter) => Promise<Envelope<ExecutionDTO[]>>>()

beforeEach(() => {
  list.mockReset()
  list.mockResolvedValue(ok([]))
  installApi({
    servers: { list: async () => ok([server()]) },
    executions: { list, get: async () => ok({}), output: async () => ok({ text: '', nextSeq: 0, done: true, truncated: false, status: 'completed' }), clear: async () => ok({ cleared: 0 }) }
  })
})

afterEach(cleanup)

describe('History filters', () => {
  it('loads the default page and refetches with each filter applied', async () => {
    render(<History />)
    await waitFor(() => expect(list).toHaveBeenCalledWith({ limit: 200 }))

    fireEvent.change(screen.getByLabelText('Source'), { target: { value: 'claude' } })
    await waitFor(() => expect(list).toHaveBeenLastCalledWith({ limit: 200, source: 'claude' }))

    fireEvent.change(screen.getByLabelText('Server'), { target: { value: 'srv-1' } })
    await waitFor(() => expect(list).toHaveBeenLastCalledWith({ limit: 200, source: 'claude', serverId: 'srv-1' }))

    fireEvent.change(screen.getByLabelText('Risk level'), { target: { value: 'HIGH' } })
    await waitFor(() => expect(list).toHaveBeenLastCalledWith({ limit: 200, source: 'claude', serverId: 'srv-1', level: 'HIGH' }))

    fireEvent.change(screen.getByLabelText('Status'), { target: { value: 'failed' } })
    await waitFor(() => expect(list).toHaveBeenLastCalledWith({ limit: 200, source: 'claude', serverId: 'srv-1', level: 'HIGH', status: 'failed' }))
  })

  it('shows the empty state when a filter returns no rows', async () => {
    render(<History />)
    expect(await screen.findByText('No matching command executions.')).toBeTruthy()
  })
})
