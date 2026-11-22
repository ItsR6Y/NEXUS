import { describe, expect, it } from 'vitest'
import { StreamRedactor, redactText, redactValue } from '../../src/main/core/security/redaction'

describe('secret redaction', () => {
  it('redacts known credential patterns and exact stored secrets', () => {
    const sample = [
      'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTYifQ.sig1234567890',
      'AWS_KEY=AKIAIOSFODNN7EXAMPLE',
      'mysql -u root --password=supersecretpass',
      'https://admin:topsecret99@internal.local/api',
      'my exact secret hunter2-canary-value appears here'
    ].join('\n')

    const clean = redactText(sample, ['hunter2-canary-value'])
    expect(clean).not.toContain('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9')
    expect(clean).not.toContain('AKIAIOSFODNN7EXAMPLE')
    expect(clean).not.toContain('supersecretpass')
    expect(clean).not.toContain('topsecret99')
    expect(clean).not.toContain('hunter2-canary-value')
  })

  it('redacts private key blocks in one-shot and streaming modes', () => {
    const pem = 'prefix\n-----BEGIN OPENSSH PRIVATE KEY-----\nAAAAB3NzaC1yc2EAAAADAQABAAABAQTestKeyBody\n-----END OPENSSH PRIVATE KEY-----\nsuffix\n'
    expect(redactText(pem)).not.toContain('AAAAB3NzaC1yc2EAAAADAQABAAABAQTestKeyBody')

    const sr = new StreamRedactor(() => ['chunked-secret-canary'])
    let out = ''
    out += sr.push('hello chunked-')
    out += sr.push('secret-canary world\n')
    out += sr.push('-----BEGIN RSA PRIVATE KEY-----\n')
    out += sr.push('MIIEpAIBAAKCAQEAsecretline\n')
    out += sr.push('-----END RSA PRIVATE KEY-----\n')
    out += sr.flush()

    expect(out).not.toContain('chunked-secret-canary')
    expect(out).not.toContain('MIIEpAIBAAKCAQEAsecretline')
    expect(out).toContain('[REDACTED PRIVATE KEY]')
  })

  it('redacts short exact secrets and concatenated CLI password forms', () => {
    // Exact (non-pattern) matching must not impose a minimum length.
    expect(redactText('token value is Q7 here', ['Q7'])).not.toContain('Q7')
    // mysql -pSECRET and curl -u user:SECRET
    expect(redactText('mysql -pS3cr3tVal nexus')).not.toContain('S3cr3tVal')
    expect(redactText('curl -u deploy:hunterpass https://internal/api')).not.toContain('hunterpass')
    // A bare -p (password prompt) is not a secret and must survive untouched.
    expect(redactText('mysql -p nexus')).toContain('-p nexus')
  })

  it('suppresses a newline-free PEM body split across chunk boundaries', () => {
    const pem = '-----BEGIN OPENSSH PRIVATE KEY-----' + 'B'.repeat(8000) + '-----END OPENSSH PRIVATE KEY-----'
    const sr = new StreamRedactor()
    let out = ''
    for (let i = 0; i < pem.length; i += 64) out += sr.push(pem.slice(i, i + 64))
    out += sr.flush()
    expect(out).not.toContain('-----BEGIN')
    expect(out).not.toContain('B'.repeat(64))
  })

  it('expands the secret list once per push rather than once per line', () => {
    let calls = 0
    const sr = new StreamRedactor(() => { calls++; return ['canary-secret'] })

    sr.push('one\ncanary-secret two\nthree\n')
    expect(calls).toBe(1)

    sr.push('partial-canary')
    expect(calls).toBe(2)
    sr.flush()
    expect(calls).toBe(3)
    expect(sr.push('a\u001b[31m\n')).toBe('a\u001b[31m\n')
  })

  it('deeply redacts nested objects', () => {
    const res = redactValue({ a: { token: 'password=my-secret-pass', list: ['hunter2-canary'] } }, ['hunter2-canary'])
    expect(JSON.stringify(res)).not.toContain('my-secret-pass')
    expect(JSON.stringify(res)).not.toContain('hunter2-canary')
  })
})
