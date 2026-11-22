import { randomUUID } from 'node:crypto'
import type { Db } from '../database'
import type { ApprovalPolicy } from '../../../../shared/policy-types'
import type { AuthType, KnownHostDTO, SecretKind } from '../../../../shared/types'

export interface ServerRow {
  id: string
  name: string
  host: string
  port: number
  username: string
  authType: AuthType
  keyPath: string | null
  approvalPolicy: ApprovalPolicy
  mcpAccessEnabled: boolean
  createdAt: number
  updatedAt: number
}

export interface ServerFields {
  name: string
  host: string
  port: number
  username: string
  authType: AuthType
  keyPath?: string | null
  approvalPolicy: ApprovalPolicy
  mcpAccessEnabled: boolean
}

interface RawServer {
  id: string
  name: string
  host: string
  port: number
  username: string
  auth_type: AuthType
  key_path: string | null
  approval_policy: ApprovalPolicy
  mcp_access_enabled: number
  created_at: number
  updated_at: number
}

const mapServer = (r: RawServer): ServerRow => ({
  id: r.id,
  name: r.name,
  host: r.host,
  port: r.port,
  username: r.username,
  authType: r.auth_type,
  keyPath: r.key_path,
  approvalPolicy: r.approval_policy,
  mcpAccessEnabled: r.mcp_access_enabled === 1,
  createdAt: r.created_at,
  updatedAt: r.updated_at
})

export class ServerRepo {
  constructor(private db: Db) {}

  create(f: ServerFields, now = Date.now()): ServerRow {
    const id = randomUUID()
    this.db
      .prepare(
        'INSERT INTO servers (id,name,host,port,username,auth_type,key_path,approval_policy,mcp_access_enabled,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)'
      )
      .run(id, f.name, f.host, f.port, f.username, f.authType, f.keyPath ?? null, f.approvalPolicy, f.mcpAccessEnabled ? 1 : 0, now, now)
    const row = this.get(id)
    if (!row) throw new Error('failed to load created server')
    return row
  }

  get(id: string): ServerRow | null {
    const r = this.db.prepare('SELECT * FROM servers WHERE id=?').get(id) as RawServer | undefined
    return r ? mapServer(r) : null
  }

  list(): ServerRow[] {
    return (this.db.prepare('SELECT * FROM servers ORDER BY name COLLATE NOCASE').all() as RawServer[]).map(mapServer)
  }

  update(id: string, patch: Partial<ServerFields>, now = Date.now()): ServerRow | null {
    const cur = this.get(id)
    if (!cur) return null
    const n = {
      name: patch.name ?? cur.name,
      host: patch.host ?? cur.host,
      port: patch.port ?? cur.port,
      username: patch.username ?? cur.username,
      authType: patch.authType ?? cur.authType,
      keyPath: patch.keyPath !== undefined ? patch.keyPath : cur.keyPath,
      approvalPolicy: patch.approvalPolicy ?? cur.approvalPolicy,
      mcpAccessEnabled: patch.mcpAccessEnabled ?? cur.mcpAccessEnabled
    }
    this.db
      .prepare('UPDATE servers SET name=?,host=?,port=?,username=?,auth_type=?,key_path=?,approval_policy=?,mcp_access_enabled=?,updated_at=? WHERE id=?')
      .run(n.name, n.host, n.port, n.username, n.authType, n.keyPath ?? null, n.approvalPolicy, n.mcpAccessEnabled ? 1 : 0, now, id)
    return this.get(id)
  }

  delete(id: string): boolean {
    return this.db.prepare('DELETE FROM servers WHERE id=?').run(id).changes === 1
  }
}

export class CredentialRefRepo {
  constructor(private db: Db) {}

  put(serverId: string, kind: SecretKind, blob: Buffer, now = Date.now()): string {
    const id = randomUUID()
    this.db
      .prepare(
        `INSERT INTO credential_refs (id,server_id,kind,blob,created_at) VALUES (?,?,?,?,?)
         ON CONFLICT(server_id,kind) DO UPDATE SET id=excluded.id, blob=excluded.blob, created_at=excluded.created_at`
      )
      .run(id, serverId, kind, new Uint8Array(blob), now)
    return id
  }

  getBlob(serverId: string, kind: SecretKind): Buffer | null {
    const r = this.db.prepare('SELECT blob FROM credential_refs WHERE server_id=? AND kind=?').get(serverId, kind) as { blob: Uint8Array } | undefined
    return r ? Buffer.from(r.blob) : null
  }

  kinds(serverId: string): SecretKind[] {
    return (this.db.prepare('SELECT kind FROM credential_refs WHERE server_id=?').all(serverId) as { kind: SecretKind }[]).map((r) => r.kind)
  }

  delete(serverId: string, kind: SecretKind): boolean {
    return this.db.prepare('DELETE FROM credential_refs WHERE server_id=? AND kind=?').run(serverId, kind).changes > 0
  }

  deleteAll(serverId: string): void {
    this.db.prepare('DELETE FROM credential_refs WHERE server_id=?').run(serverId)
  }

  allBlobs(): { serverId: string; kind: SecretKind; blob: Buffer }[] {
    return (this.db.prepare('SELECT server_id, kind, blob FROM credential_refs').all() as { server_id: string; kind: SecretKind; blob: Uint8Array }[]).map(
      (r) => ({ serverId: r.server_id, kind: r.kind, blob: Buffer.from(r.blob) })
    )
  }
}

interface RawKnownHost {
  host: string
  port: number
  key_type: string
  fingerprint_sha256: string
  first_seen_at: number
  last_seen_at: number
}

const mapKnownHost = (r: RawKnownHost): KnownHostDTO => ({
  host: r.host,
  port: r.port,
  keyType: r.key_type,
  fingerprintSha256: r.fingerprint_sha256,
  firstSeenAt: r.first_seen_at,
  lastSeenAt: r.last_seen_at
})

export class KnownHostRepo {
  constructor(private db: Db) {}

  get(host: string, port: number, keyType: string): KnownHostDTO | null {
    const r = this.db
      .prepare('SELECT * FROM known_hosts WHERE host=? AND port=? AND key_type=?')
      .get(host, port, keyType) as RawKnownHost | undefined
    return r ? mapKnownHost(r) : null
  }

  listForEndpoint(host: string, port: number): KnownHostDTO[] {
    return (this.db.prepare('SELECT * FROM known_hosts WHERE host=? AND port=? ORDER BY last_seen_at DESC').all(host, port) as RawKnownHost[]).map(mapKnownHost)
  }

  list(): KnownHostDTO[] {
    return (this.db.prepare('SELECT * FROM known_hosts ORDER BY host COLLATE NOCASE, port, key_type').all() as RawKnownHost[]).map(mapKnownHost)
  }

  insert(host: string, port: number, keyType: string, fingerprintSha256: string, now = Date.now()): KnownHostDTO {
    this.db
      .prepare(
        `INSERT INTO known_hosts (host,port,key_type,fingerprint_sha256,first_seen_at,last_seen_at) VALUES (?,?,?,?,?,?)
         ON CONFLICT(host,port,key_type) DO UPDATE SET fingerprint_sha256=excluded.fingerprint_sha256, last_seen_at=excluded.last_seen_at`
      )
      .run(host, port, keyType, fingerprintSha256, now, now)
    const row = this.get(host, port, keyType)
    if (!row) throw new Error('failed to load known host')
    return row
  }

  touch(host: string, port: number, keyType: string, now = Date.now()): void {
    this.db.prepare('UPDATE known_hosts SET last_seen_at=? WHERE host=? AND port=? AND key_type=?').run(now, host, port, keyType)
  }

  remove(host: string, port: number, keyType: string): boolean {
    return this.db.prepare('DELETE FROM known_hosts WHERE host=? AND port=? AND key_type=?').run(host, port, keyType).changes > 0
  }
}
