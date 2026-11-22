import { DatabaseSync, type SQLInputValue, type StatementSync } from 'node:sqlite'
import { copyFileSync, existsSync } from 'node:fs'
import { MIGRATIONS } from './migrations'

export interface RunResult {
  changes: number
  lastInsertRowid: number
}

export interface PreparedStatement {
  get(...params: SQLInputValue[]): unknown
  all(...params: SQLInputValue[]): unknown[]
  run(...params: SQLInputValue[]): RunResult
  iterate(...params: SQLInputValue[]): IterableIterator<unknown>
}

export interface Db {
  exec(sql: string): void
  prepare(sql: string): PreparedStatement
  pragma(sql: string): void
  transaction<T>(fn: () => T): () => T
  close(): void
}

export interface Migration {
  version: number
  name: string
  sql: string
}

export class MigrationError extends Error {
  constructor(public readonly version: number, cause: unknown) {
    super(`Migration ${version} failed: ${cause instanceof Error ? cause.message : String(cause)}`)
    this.name = 'MigrationError'
  }
}

class NodeSqliteDb implements Db {
  private readonly raw: DatabaseSync
  private txDepth = 0

  constructor(file: string) {
    this.raw = new DatabaseSync(file)
  }

  exec(sql: string): void {
    this.raw.exec(sql)
  }

  pragma(sql: string): void {
    this.raw.exec(`PRAGMA ${sql}`)
  }

  prepare(sql: string): PreparedStatement {
    const stmt: StatementSync = this.raw.prepare(sql)
    return {
      get: (...params: SQLInputValue[]) => stmt.get(...params),
      all: (...params: SQLInputValue[]) => stmt.all(...params),
      run: (...params: SQLInputValue[]) => {
        const res = stmt.run(...params)
        return { changes: Number(res.changes), lastInsertRowid: Number(res.lastInsertRowid) }
      },
      iterate: (...params: SQLInputValue[]): IterableIterator<unknown> =>
        typeof stmt.iterate === 'function'
          ? (stmt.iterate(...params) as IterableIterator<unknown>)
          : stmt.all(...params)[Symbol.iterator]()
    }
  }

  transaction<T>(fn: () => T): () => T {
    return () => {
      const sp = `sp_${++this.txDepth}`
      this.raw.exec(this.txDepth === 1 ? 'BEGIN IMMEDIATE' : `SAVEPOINT ${sp}`)
      try {
        const out = fn()
        this.raw.exec(this.txDepth === 1 ? 'COMMIT' : `RELEASE SAVEPOINT ${sp}`)
        this.txDepth--
        return out
      } catch (e) {
        try {
          this.raw.exec(this.txDepth === 1 ? 'ROLLBACK' : `ROLLBACK TO SAVEPOINT ${sp}`)
        } catch {
          /* ignore rollback failure */
        }
        this.txDepth--
        throw e
      }
    }
  }

  close(): void {
    this.raw.close()
  }
}

/** Open (or create) the SQLite database using built-in node:sqlite, apply pragmas, and run pending migrations. */
export function openDatabase(file: string, migrations: Migration[] = MIGRATIONS): Db {
  const inMemory = file === ':memory:'
  const db = new NodeSqliteDb(file)
  db.pragma('foreign_keys = ON')
  db.pragma('busy_timeout = 5000')
  if (!inMemory) db.pragma('journal_mode = WAL')
  try {
    runMigrations(db, file, migrations)
  } catch (e) {
    db.close()
    throw e
  }
  return db
}

export function appliedVersions(db: Db): number[] {
  const t = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='schema_migrations'").get()
  if (!t) return []
  return (db.prepare('SELECT version FROM schema_migrations ORDER BY version').all() as { version: number }[]).map((r) => r.version)
}

export function runMigrations(db: Db, file: string, migrations: Migration[]): void {
  const sorted = [...migrations].sort((a, b) => a.version - b.version)
  sorted.forEach((m, i) => {
    if (m.version !== i + 1) throw new Error(`Migration versions must be sequential from 1 (found ${m.version} at position ${i + 1})`)
  })
  db.exec('CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at INTEGER NOT NULL)')
  const applied = new Set(appliedVersions(db))
  const maxKnown = sorted.length
  for (const v of applied) {
    if (v > maxKnown) throw new Error(`Database schema version ${v} is newer than this app supports (${maxKnown})`)
  }
  const pending = sorted.filter((m) => !applied.has(m.version))
  if (pending.length === 0) return
  if (file !== ':memory:' && applied.size > 0 && existsSync(file)) {
    db.pragma('wal_checkpoint(TRUNCATE)')
    copyFileSync(file, `${file}.bak`)
  }
  for (const m of pending) {
    try {
      db.transaction(() => {
        db.exec(m.sql)
        db.prepare('INSERT INTO schema_migrations (version, name, applied_at) VALUES (?,?,?)').run(m.version, m.name, Date.now())
      })()
    } catch (e) {
      throw new MigrationError(m.version, e)
    }
  }
}
