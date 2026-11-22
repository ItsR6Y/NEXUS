import type { Db } from '../database'
import { DEFAULT_SETTINGS, SettingsPatchSchema, SettingsSchema, type Settings } from '../../../../shared/ipc'

export class SettingsRepo {
  constructor(private db: Db) {}

  getAll(): Settings {
    const rows = this.db.prepare('SELECT key, value FROM settings').all() as { key: string; value: string }[]
    const stored: Record<string, unknown> = {}
    for (const r of rows) {
      try {
        if (r.key in DEFAULT_SETTINGS) stored[r.key] = JSON.parse(r.value)
      } catch {
        /* ignore corrupt value */
      }
    }
    const merged = { ...DEFAULT_SETTINGS, ...stored }
    const parsed = SettingsSchema.safeParse(merged)
    return parsed.success ? parsed.data : { ...DEFAULT_SETTINGS }
  }

  patch(patch: unknown): Settings {
    const p = SettingsPatchSchema.parse(patch)
    const stmt = this.db.prepare('INSERT INTO settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value')
    this.db.transaction(() => {
      for (const [k, v] of Object.entries(p)) stmt.run(k, JSON.stringify(v))
    })()
    return this.getAll()
  }
}
