// measure.mjs MODE ... — run by studio/build.sh inside a container of the built image
// (node only, no network) to measure the server. Modes:
//   wait SECONDS              until GET /api/platform/profile is answered by the server: 401, as the
//                             request carries no assertion (exit 1 at the deadline)
//   listen SECONDS            the first listening TCP socket, as "address:port" (exit 1 at the deadline)
//   encoding PATH             the content-encoding answered to a request accepting br, gzip and zstd
//   matrix FILE               one request per line "kind<TAB>method<TAB>path[<TAB>header:value]";
//                             prints "kind<TAB>method<TAB>path<TAB>status"
//   mark DIR                  in a copy of the server bundle DIR, a first middleware that logs every request
//   importers DIR TEXT        the modules of the server bundle DIR importing statically a module whose
//                             text holds TEXT (a module comment naming a package path)
//   listener DIR              the environment names the built listener path reads (the node-server
//                             preset's module, srvx's port, host and TLS resolution), sorted; fails on
//                             a missing anchor or an environment access of another shape
import fs from 'node:fs'
import http from 'node:http'

const [mode, arg] = process.argv.slice(2)

function req(method, path, headers = {}) {
  return new Promise((resolve, reject) => {
    const r = http.request({ host: '127.0.0.1', port: 3000, method, path, headers }, (res) => {
      const chunks = []
      res.on('data', (c) => chunks.push(c))
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }))
    })
    r.setTimeout(30000, () => r.destroy(new Error('timeout')))
    r.on('error', reject)
    r.end()
  })
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))
const lines = (f) => fs.readFileSync(f, 'utf8').split('\n').filter((l) => l !== '')

function listening() {
  for (const f of ['/proc/net/tcp', '/proc/net/tcp6']) {
    for (const l of fs.readFileSync(f, 'utf8').split('\n').slice(1)) {
      const c = l.trim().split(/\s+/)
      if (c[3] !== '0A') continue // LISTEN
      const [addr, port] = c[1].split(':')
      let a
      if (addr.length === 8) a = Buffer.from(addr, 'hex').reverse().join('.')
      else a = addr === '0'.repeat(32) ? '::' : addr
      return `${a}:${parseInt(port, 16)}`
    }
  }
  return null
}

switch (mode) {
  case 'wait': {
    const end = Date.now() + Number(arg) * 1000
    for (;;) {
      try {
        if ((await req('GET', '/api/platform/profile')).status === 401) process.exit(0)
      } catch {}
      if (Date.now() > end) process.exit(1)
      await sleep(500)
    }
  }
  case 'listen': {
    const end = Date.now() + Number(arg) * 1000
    for (;;) {
      const l = listening()
      if (l) {
        console.log(l)
        process.exit(0)
      }
      if (Date.now() > end) process.exit(1)
      await sleep(250)
    }
  }
  case 'encoding': {
    const r = await req('GET', arg, { 'accept-encoding': 'br, gzip, zstd' })
    console.log(`${r.status} ${r.headers['content-encoding'] ?? 'identity'}`)
    break
  }
  case 'matrix':
    for (const l of lines(arg)) {
      const [kind, method, path, header] = l.split('\t')
      const headers = { accept: 'text/html' }
      if (header) {
        const i = header.indexOf(':')
        headers[header.slice(0, i)] = header.slice(i + 1)
      }
      let status
      try {
        status = (await req(method, path, headers)).status
      } catch (e) {
        status = `error ${e.message}`
      }
      console.log(`${kind}\t${method}\t${path}\t${status}`)
    }
    break
  case 'mark': {
    // in a copy of the server bundle (DIR): put a request middleware first in the start
    // instance's chain that logs "[sp-marker] METHOD PATH" for every request entering it
    const path = await import('node:path')
    const ssr = path.join(arg, '_ssr')
    const hits = fs.readdirSync(ssr).filter((f) => {
      const t = fs.readFileSync(path.join(ssr, f), 'utf8')
      return t.includes('createStart(') && /requestMiddleware:\s*\[/.test(t)
    })
    if (hits.length !== 1) {
      console.error(`mark: ${hits.length} modules define the start instance`)
      process.exit(1)
    }
    const file = path.join(ssr, hits[0])
    let t = fs.readFileSync(file, 'utf8')
    const factory = t.match(/([A-Za-z_$][\w$]*)\(\{\s*type:\s*"request"\s*\}\)/)
    const lists = t.match(/requestMiddleware:\s*\[/g) ?? []
    const start = t.search(/^.*createStart\(/m)
    if (!factory || lists.length !== 1 || start < 0) {
      console.error('mark: the start instance has an unexpected shape')
      process.exit(1)
    }
    const marker =
      `var __spMarker = ${factory[1]}({ type: "request" }).server(({ request, next }) => {\n` +
      `\tconsole.log("[sp-marker] " + request.method + " " + new URL(request.url).pathname);\n\treturn next();\n});\n`
    t = t.slice(0, start) + marker + t.slice(start)
    t = t.replace(/requestMiddleware:\s*\[/, 'requestMiddleware: [__spMarker, ')
    fs.writeFileSync(file, t)
    console.log(hits[0])
    break
  }
  case 'listener': {
    const path = await import('node:path')
    const files = fs.readdirSync(arg, { recursive: true }).filter((f) => f.endsWith('.mjs'))
    const text = (f) => fs.readFileSync(path.join(arg, f), 'utf8')
    const fail = (m) => {
      console.error(`listener: ${m}`)
      process.exit(1)
    }
    const parts = []
    // the preset's module: from its module comment to the next module comment
    const anchor = /^\/\/ [^\n]*\/nitro\/dist\/presets\/node\/runtime\/node-server\.mjs$/m
    const presets = files.filter((f) => anchor.test(text(f)))
    if (presets.length !== 1) fail(`${presets.length} modules hold the node-server preset`)
    const t = text(presets[0])
    const from = t.search(anchor)
    const rest = t.slice(t.indexOf('\n', from) + 1)
    const end = rest.search(/^\/\/ (?:\.\.\/|#region)/m)
    parts.push(end < 0 ? rest : rest.slice(0, end))
    // srvx's resolution of the port, the host and the TLS pair
    for (const fn of ['resolvePortAndHost', 'resolveTLSOptions', 'resolveCertOrKey']) {
      const defs = files.filter((f) => text(f).includes(`function ${fn}(`))
      if (defs.length !== 1) fail(`${defs.length} modules define ${fn}`)
      const u = text(defs[0])
      const open = u.indexOf('{', u.indexOf(`function ${fn}(`))
      let depth = 0
      let i = open
      for (; i < u.length; i++) {
        if (u[i] === '{') depth++
        else if (u[i] === '}' && --depth === 0) break
      }
      parts.push(u.slice(open, i + 1))
    }
    const names = new Set()
    const read = /(?:globalThis\.)?process\??\.env\??\.([A-Za-z_$][\w$]*)/g
    for (const p of parts) {
      for (const m of p.matchAll(read)) names.add(m[1])
      if (/\benv\b|process\s*\[/.test(p.replace(read, ''))) fail('an environment access of another shape')
    }
    for (const n of [...names].sort()) console.log(n)
    break
  }
  case 'importers': {
    // the modules of the server bundle (DIR) that import statically a module holding the third
    // argument (a module comment naming a package path); printed without the content hash
    const [dir, needle] = [arg, process.argv[4]]
    const path = await import('node:path')
    const files = fs.readdirSync(dir, { recursive: true }).filter((f) => f.endsWith('.mjs'))
    const importedBy = new Map()
    // static imports only (from "x", import "x"): a module evaluated when its importer is;
    // import("x") loads it only when that code runs
    const spec = /(?:\bfrom\s*|\bimport\s*)["'](\.{1,2}\/[^"']+)["']/g
    for (const f of files) {
      for (const m of fs.readFileSync(path.join(dir, f), 'utf8').matchAll(spec)) {
        const target = path.normalize(path.join(path.dirname(f), m[1]))
        if (!importedBy.has(target)) importedBy.set(target, new Set())
        importedBy.get(target).add(f)
      }
    }
    const matched = files.filter((f) => fs.readFileSync(path.join(dir, f), 'utf8').includes(needle))
    if (matched.length === 0) {
      console.error(`no module of the bundle matches ${needle}`)
      process.exit(1)
    }
    const seen = new Set(matched.flatMap((m) => [...(importedBy.get(m) ?? [])]))
    for (const f of [...new Set([...seen].map((f) => f.replace(/-[A-Za-z0-9_-]{8}\.mjs$/, '.mjs')))].sort()) console.log(f)
    break
  }
  default:
    console.error(`unknown mode ${mode}`)
    process.exit(2)
}
