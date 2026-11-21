// SPDX-License-Identifier: Apache-2.0
// paths.mjs SRV <paths.in >paths.json — how the built server reads request paths.
// paths.mjs SRV --routes               — what the build serves, from its own route tree.
//
// SRV is a build's output directory (.output). The script starts that server itself, in this
// process and on the loopback interface, sends it every path as raw bytes of an HTTP/1.1
// request line, and records what the server's own code made of each:
//   raw       the path as sent
//   href      the request's URL as the server's URL parser left it, without the origin;
//             null when the server refused the request before reading a path (400)
//   segments  the path's segments as the router matches on them; null when no router was
//             asked (a refusal, or a redirect the server answers before routing)
//   route     the full path of the route the built route tree matches exactly, or null
// one JSON object per line, inside one JSON array.
//
// Nothing here re-implements the server. The entry points into the build, found by the names
// its chunks export:
//   - server/index.mjs: the whole server; importing it listens on HOST and PORT;
//   - the chunk exporting `startInstance`: the request-middleware chain is replaced, for this
//     run, by one observer that records the URL and the path a middleware is handed;
//   - the chunk exporting `getRouter`: the application's router with the built route tree; a
//     server middleware put on its root route records the path the router matched on and
//     answers, so that no handler and no page runs;
//   - the chunk exporting `readPath`: the request guard's own reading of a path. It must give
//     the segments and the route the router gave, for every path, or the script fails.
// With --routes nothing is started and nothing is read from standard input: the script prints
// one line per route of the built route tree, KIND<TAB>FULL PATH<TAB>METHODS — api for a path
// under /api, else page; the methods of its server handlers, sorted and comma-separated, or -
// — and one line function<TAB>ID<TAB>- per server function the bundle registers.
//
// The server is started as the build's prerender starts it — TSS_PRERENDERING, no setting of
// a node — which is the one way it starts without them.
//
// Facts this script holds, and fails on when they change:
//   - a path under /_serverFn/ is dispatched by its prefix and never reaches the route tree;
//   - a plain path, a path behind a dot-dot segment, the same percent-encoded, and a path
//     with a static segment in capitals all match the route of the plain path;
//   - every route of the tree is matched by its own plain form.
import { readdirSync, readFileSync } from 'node:fs'
import net from 'node:net'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'

const srv = process.argv[2]
if (!srv) {
  console.error('usage: paths.mjs SRV <paths.in >paths.json')
  process.exit(2)
}
const fail = (what) => {
  console.error(`paths.mjs: ${what}`)
  process.exit(1)
}
const OWN = 'aaaaaaaaaaaaaaaaaaa1'
const FOREIGN = 'bbbbbbbbbbbbbbbbbbb2'
const PORT = 3000

// The paths on standard input, read before anything of the server is loaded: once the server
// is in the process a read of standard input no longer waits for its bytes, and a list that
// arrives late would be an error the server's own handlers swallow.
const input = process.argv[3] === '--routes' ? '' : readFileSync(0, 'latin1')

// stdout is the vectors alone: whatever the server prints goes to stderr
console.log = console.info = console.warn = console.error
for (const name of Object.keys(process.env)) {
  if (/^(SUPAPACE_|NITRO_|TSS_)/.test(name)) delete process.env[name]
}
Object.assign(process.env, { TSS_PRERENDERING: 'true', HOST: '127.0.0.1', PORT: String(PORT) })

// --- the build's entry points -------------------------------------------------------------
const ssr = join(srv, 'server', '_ssr')
async function exported(name) {
  const hits = []
  for (const file of readdirSync(ssr).sort()) {
    if (!file.endsWith('.mjs')) continue
    const list = /\nexport \{([^}]*)\};?\s*$/.exec(readFileSync(join(ssr, file), 'utf8'))
    const names = list ? list[1].split(',').map((e) => e.trim().split(' as ').pop()) : []
    if (!names.includes(name) && !names.some((n) => n.endsWith('_exports'))) continue
    const mod = await import(pathToFileURL(join(ssr, file)).href)
    for (const value of [mod, ...Object.values(mod)]) {
      if (value && typeof value === 'object' && name in value) hits.push(value[name])
    }
  }
  const distinct = [...new Set(hits)]
  if (distinct.length !== 1) fail(`${distinct.length} values are exported as ${name} by the server's chunks`)
  return distinct[0]
}
const getRouter = await exported('getRouter')
const startInstance = await exported('startInstance')
const readPath = await exported('readPath')
const router = getRouter()

if (process.argv[3] === '--routes') {
  const lines = []
  for (const route of Object.values(router.routesById)) {
    // a route with a path of its own: not the root, not a layout without one
    if (route.id === '__root__' || !route.path) continue
    const own = route.options?.server?.handlers
    lines.push(`${route.fullPath.startsWith('/api/') ? 'api' : 'page'}\t${route.fullPath}\t${own ? Object.keys(own).sort().join(',') : '-'}`)
  }
  for (const file of readdirSync(ssr)) {
    if (!file.endsWith('.mjs')) continue
    for (const m of readFileSync(join(ssr, file), 'utf8').matchAll(/createServerRpc\(\{\s*id: "([^"]+)"/g)) lines.push(`function\t${m[1]}\t-`)
  }
  process.stdout.write([...new Set(lines)].sort().join('\n') + '\n', () => process.exit(0))
  await new Promise(() => {})
}

const seen = new Map()
const record = (ctx) => {
  const n = ctx.request.headers.get('x-n')
  if (!seen.has(n)) seen.set(n, {})
  return seen.get(n)
}
const observer = (server) => ({ options: { type: 'request', server } })
startInstance.getOptions = () => ({
  requestMiddleware: [
    observer((ctx) => {
      Object.assign(record(ctx), { href: ctx.request.url, handed: ctx.pathname, type: ctx.handlerType })
      return ctx.next()
    }),
  ],
})
router.routeTree.options.server = {
  middleware: [
    observer((ctx) => {
      record(ctx).matchedOn = ctx.pathname
      return new Response(null, { status: 204 })
    }),
  ],
}
await import(pathToFileURL(join(srv, 'server', 'index.mjs')).href)

// --- the paths ----------------------------------------------------------------------------
const fixed = input
  .split('\n')
  .filter((l) => l.startsWith('/'))
if (fixed.length === 0) fail('no path on standard input')

/** A route's full path with its parameters filled in: $ref with the request's project. */
const fill = (path) =>
  path
    .split('/')
    .map((s) => (s === '$ref' ? OWN : s.startsWith('$') ? 'x1' : s))
    .join('/')
const hex = (c) => `%${c.charCodeAt(0).toString(16).padStart(2, '0')}`
/** The filled-in path with its first static segment in capitals. */
function firstInCapitals(template) {
  const at = template.split('/').slice(1).findIndex((x) => !x.startsWith('$'))
  return '/' + fill(template).split('/').slice(1).map((x, i) => (i === at ? x.toUpperCase() : x)).join('/')
}

function forms(template) {
  const t = template.split('/').slice(1) // the template's segments: '$name' is a parameter
  const s = fill(template).split('/').slice(1) // the same, filled in
  const p = '/' + s.join('/')
  const isStatic = (i) => !t[i].startsWith('$')
  const firstStatic = t.findIndex((_, i) => isStatic(i))
  const out = [
    p,
    `${p}/`,
    `${p}%20`,
    `${p}%20?`,
    `${p}%20?&`,
    `${p}%20?x=1`,
    `${p}%20%20`,
    `${p}/%20`,
    `${p}/x/..%20`,
    `${p}/.%20`,
    `/x/..${p}`,
    `/x/%2e%2e${p}`,
    `/x/.%2E${p}`,
    `/x/%252e%252e${p}`,
    `/x/%C0%AE%C0%AE${p}`,
    p.toUpperCase(),
    firstInCapitals(template),
    `/${p}`,
    '/' + s.join('\\'),
    '/' + s.join('%5c'),
    s.length > 1 ? '/' + s.join('%2f') : `${p}%2f`,
    `/${s[0]}%00${s.length > 1 ? '/' + s.slice(1).join('/') : ''}`,
    `/${s[0]}\x01${s.length > 1 ? '/' + s.slice(1).join('/') : ''}`,
    `${p}#`,
    `${p}#/../x`,
  ]
  if (s.length > 1) out.push(`/${s[0]}//${s.slice(1).join('/')}`)
  for (let i = 0; i < s.length; i++) {
    const withRef = (ref) => '/' + s.map((x, j) => (j === i ? ref : x)).join('/')
    out.push(withRef(FOREIGN), withRef(FOREIGN.toUpperCase()))
    if (i < s.length - 1) out.push(`/${s.slice(0, i + 1).join('/')}#/${s.slice(i + 1).join('/')}`)
  }
  if (firstStatic >= 0) {
    const letter = /[a-z]/.exec(s[firstStatic])
    const encode = (to) =>
      '/' + s.map((x, i) => (i === firstStatic && letter ? x.replace(letter[0], to(letter[0])) : x)).join('/')
    out.push(encode(hex), encode((c) => hex(c).replace('%', '%25')))
    const k = t.findIndex((x, i) => isStatic(i) && x.includes('k'))
    if (k >= 0) out.push('/' + s.map((x, i) => (i === k ? x.replace('k', '%E2%84%AA') : x)).join('/'))
  }
  if (s[0] === 'api' && s.length > 1) {
    const rest = s.slice(1).join('/')
    out.push(`/api%20/${rest}`, `/%20api/${rest}`, `/%2561pi/${rest}`)
  }
  return out
}

const templates = [
  ...new Set(
    Object.values(router.routesById)
      .map((r) => r.fullPath)
      .filter((path) => typeof path === 'string' && path.startsWith('/'))
      .map((path) => (path.length > 1 ? path.replace(/\/+$/, '') : path))
  ),
].sort()
if (templates.length < 2) fail('the built route tree has no routes')

/**
 * Every octet, percent-encoded, at the edges of three paths: a route of the request's own
 * project (what is forwarded must be read alike on both sides), a page of another project and
 * a route that is not served (what must be refused on both). The paths are chosen by rule from
 * the route tree, so the sweep follows it: an octet a parser strips, resolves or reads as a
 * delimiter at the end of a path, in a segment of its own, or beside the first segment shows
 * here whatever the octet is.
 */
function sweep() {
  const own = templates.find((t) => t.startsWith('/api/') && t.includes('/$ref') && !/^\/api\/(ai|mcp)(\/|$)/.test(t))
  const page = templates.find((t) => !t.startsWith('/api/') && t.endsWith('/$ref'))
  const optIn = templates.find((t) => t === '/api/mcp')
  if (!own || !page || !optIn) fail('the built route tree lacks a route the octet sweep is anchored on')
  const out = []
  for (const a of [fill(own), fill(page).replace(OWN, FOREIGN), optIn]) {
    const [first, ...rest] = a.split('/').slice(1)
    for (let b = 0; b < 256; b++) {
      const e = `%${b.toString(16).padStart(2, '0')}`
      out.push(`${a}${e}`, `${a}${e}?`, `${a}/${e}`, `${a}/${e}?`, `/${e}${a.slice(1)}`, `/${first}${e}/${rest.join('/')}`, `${a}/x/..${e}`, `${a}/.${e}`)
      if (e !== e.toUpperCase()) out.push(`${a}${e.toUpperCase()}`)
    }
  }
  return out
}
const raws = [...new Set([...fixed, ...templates.flatMap((t) => (t === '/' ? ['/'] : forms(t))), ...sweep()])]

// --- one request per path, as raw bytes ---------------------------------------------------
function send(raw, n) {
  return new Promise((resolve) => {
    const socket = net.connect(PORT, '127.0.0.1')
    let head = ''
    socket.setTimeout(30_000, () => fail(`no answer for ${JSON.stringify(raw)}`))
    socket.on('connect', () =>
      socket.end(`GET ${raw} HTTP/1.1\r\nHost: localhost\r\nAccept: text/html\r\nx-n: ${n}\r\nConnection: close\r\n\r\n`, 'latin1')
    )
    socket.on('data', (d) => (head += d.toString('latin1')))
    socket.on('error', (e) => fail(`${JSON.stringify(raw)}: ${e.message}`))
    socket.on('close', () =>
      resolve({
        status: Number(/^HTTP\/1\.1 (\d{3})/.exec(head)?.[1]),
        location: /\r\nlocation: *([^\r]*)/i.exec(head)?.[1],
      })
    )
  })
}
for (let tries = 0; ; tries++) {
  const up = await new Promise((resolve) => {
    const s = net.connect(PORT, '127.0.0.1')
    s.on('connect', () => resolve(true) || s.destroy())
    s.on('error', () => resolve(false))
  })
  if (up) break
  if (tries > 200) fail('the server did not listen')
  await new Promise((r) => setTimeout(r, 50))
}

const pathOf = (href) => new URL(href, 'http://localhost').href.replace(/^[a-z]+:\/\/[^/]*/, '')
const sameSegments = (a, b) => a.length === b.length && a.every((x, i) => x === b[i])
const vectors = []
const BATCH = 16
for (let at = 0; at < raws.length; at += BATCH) {
  const batch = raws.slice(at, at + BATCH)
  const answers = await Promise.all(batch.map((raw, i) => send(raw, at + i)))
  for (const [i, raw] of batch.entries()) {
    const { status, location } = answers[i]
    const r = seen.get(String(at + i))
    let v
    if (!r) {
      // the server answered before its middleware chain: a refusal of the request line or the
      // path, or the redirect of a path that begins with two slashes
      if (status === 400) v = { raw, href: null, segments: null, route: null }
      else if (status === 308 && location) v = { raw, href: pathOf(location), segments: null, route: null }
      else fail(`${JSON.stringify(raw)} was answered ${status} outside the middleware chain`)
    } else {
      const reading = readPath(router, r.handed)
      if (r.type === 'serverFn') {
        if (r.matchedOn !== undefined) fail(`${JSON.stringify(raw)}: a server function went through the route tree`)
        v = { raw, href: pathOf(r.href), segments: reading.segments, route: null }
      } else {
        if (r.matchedOn === undefined) fail(`${JSON.stringify(raw)}: the router was not asked (status ${status})`)
        const matchedOn = r.matchedOn.replace(/\/+$/, '').split('/').slice(1)
        const [, params, found] = router.getMatchedRoutes(r.matchedOn)
        const route = found && params['**'] === undefined ? found.fullPath : null
        if (!sameSegments(reading.segments, matchedOn) || reading.route !== route) {
          fail(
            `${JSON.stringify(raw)}: the request guard reads ${JSON.stringify(reading)}, the router matched on ${JSON.stringify(r.matchedOn)} and found ${route}`
          )
        }
        v = { raw, href: pathOf(r.href), segments: matchedOn, route }
      }
    }
    vectors.push(v)
  }
}

// --- the facts ----------------------------------------------------------------------------
const by = new Map(vectors.map((v) => [v.raw, v]))
const trim = (path) => (path && path.length > 1 ? path.replace(/\/+$/, '') : path)
for (const t of templates) {
  if (t === '/') continue
  const p = fill(t)
  const plain = by.get(p)
  if (plain.href !== p || plain.route === null) fail(`${t}: its plain form ${p} reads ${JSON.stringify(plain)}`)
  const first = firstInCapitals(t)
  for (const [raw, href] of [
    [`/x/..${p}`, p],
    [`/x/%2e%2e${p}`, p],
    [first, first],
  ]) {
    const v = by.get(raw)
    if (v.href !== href || v.route !== plain.route) fail(`${raw} reads ${JSON.stringify(v)}, not the route of ${p}`)
  }
}
if (!vectors.some((v) => trim(v.route) === '/api/mcp')) fail('no path matched the route /api/mcp')
const fn = vectors.filter((v) => v.raw.startsWith('/_serverFn/'))
if (fn.length === 0) fail('no path under /_serverFn/ among the fixed lines')

process.stdout.write('[\n' + vectors.map((v) => JSON.stringify(v)).join(',\n') + '\n]\n', () => process.exit(0))
