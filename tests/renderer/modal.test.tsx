/**
 * @vitest-environment jsdom
 */
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { Modal } from '../../src/renderer/src/components/ui'

afterEach(cleanup)

describe('Modal focus management', () => {
  it('focuses the first control on open and restores the previous focus on close', () => {
    const opener = document.createElement('button')
    opener.textContent = 'opener'
    document.body.append(opener)
    opener.focus()

    const { unmount } = render(
      <Modal title="Confirm" onClose={() => {}}>
        <button type="button">one</button>
        <button type="button">two</button>
      </Modal>
    )
    expect(document.activeElement).toBe(screen.getByText('one'))

    unmount()
    expect(document.activeElement).toBe(opener)
    opener.remove()
  })

  it('cycles Tab and Shift+Tab inside the dialog instead of escaping to the page', () => {
    render(
      <Modal title="Confirm" onClose={() => {}}>
        <button type="button">one</button>
        <button type="button">two</button>
      </Modal>
    )
    const one = screen.getByText('one')
    const two = screen.getByText('two')

    two.focus()
    fireEvent.keyDown(window, { key: 'Tab' })
    expect(document.activeElement).toBe(one)

    one.focus()
    fireEvent.keyDown(window, { key: 'Tab', shiftKey: true })
    expect(document.activeElement).toBe(two)
  })

  it('closes on Escape', () => {
    const onClose = vi.fn()
    render(
      <Modal title="Confirm" onClose={onClose}>
        <button type="button">one</button>
      </Modal>
    )
    fireEvent.keyDown(window, { key: 'Escape' })
    expect(onClose).toHaveBeenCalledTimes(1)
  })
})
