export function buildCsp(dev: boolean): string {
  const directives = [
    "default-src 'self'",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    "img-src 'self' data:",
    "font-src 'self' data:",
    "style-src 'self' 'unsafe-inline'"
  ]
  directives.push(dev ? "script-src 'self' 'unsafe-inline'" : "script-src 'self'")
  directives.push(dev ? "connect-src 'self' ws://localhost:* http://localhost:*" : "connect-src 'self'")
  return directives.join('; ')
}
