import type { Migration } from '../database'
import { m001 } from './001_init'
import { m002 } from './002_indexes'

export const MIGRATIONS: Migration[] = [m001, m002]
