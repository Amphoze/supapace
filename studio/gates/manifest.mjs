// SPDX-License-Identifier: Apache-2.0
// manifest.mjs PARSER ROUTE_TREE SERVER — the served surface of a build, from its own outputs:
// the API and page routes of the regenerated route tree (ROUTE_TREE, its interface
// FileRoutesByFullPath), the methods each route's server handlers answer (the route
// registrations of the server bundle SERVER), and the server functions of the bundler's
// server-function manifest with the method each is created with; and the server's own (Nitro)
// router in SERVER/index.mjs, which may route nothing but /** to the SSR renderer and set only
// headers by its route rules. Files are parsed with the
// bundler's own parser (PARSER/node_modules/rolldown). Prints, sorted, one line per entry:
//   KIND<TAB>ID<TAB>METHODS<TAB>REF
// KIND is api (a path under /api/), page or function; ID the full path or the function id;
// METHODS the handler methods, sorted and comma-separated, or - for a route without server
// handlers; REF y when a path segment is $ref, else n. Anything of an unexpected shape is a line
//   error<TAB>WHAT
import { readFileSync, readdirSync } from 'node:fs'
import { createRequire } from 'node:module'
import { dirname, join, relative } from 'node:path'
import { pathToFileURL } from 'node:url'

const [parserDir, routeTree, server] = process.argv.slice(2)
if (!parserDir || !routeTree || !server) {
  console.error('usage: manifest.mjs PARSER ROUTE_TREE SERVER')
  process.exit(2)
}
const { parseAst } = await import(
  pathToFileURL(createRequire(join(parserDir, 'x.js')).resolve('rolldown/parseAst')).href
)
const out = []
const error = (what) => out.push(`error\t${what}`)
const parse = (file, lang) => parseAst(readFileSync(file, 'utf8'), { lang, sourceType: 'module', preserveParens: false }, file)
const str = (n) => (n?.type === 'Literal' && typeof n.value === 'string' ? n.value : null)
const key = (p) => (p.computed ? str(p.key) : p.key.type === 'Identifier' ? p.key.name : str(p.key))
const prop = (obj, name) => obj?.type === 'ObjectExpression' && obj.properties.find((p) => p.type === 'Property' && key(p) === name)

function walk(node, visit) {
  visit(node)
  for (const k in node) {
    const v = node[k]
    if (Array.isArray(v)) {
      for (const c of v) if (c && typeof c.type === 'string') walk(c, visit)
    } else if (v && typeof v.type === 'string' && k !== 'type') walk(v, visit)
  }
}

// 1. The route tree: full path -> the route's type name -> its id.
const byType = { FileRoutesByFullPath: new Map(), FileRoutesById: new Map() }
walk(parse(routeTree, 'ts'), (n) => {
  if (n.type !== 'TSInterfaceDeclaration' || !(n.id.name in byType)) return
  for (const m of n.body.body) {
    const path = m.type !== 'TSPropertySignature' ? null : m.key.type === 'Identifier' ? m.key.name : str(m.key)
    const t = m.typeAnnotation?.typeAnnotation
    if (path === null || t?.type !== 'TSTypeQuery' || t.exprName.type !== 'Identifier') {
      error(`${n.id.name}: a member of another shape`)
      continue
    }
    byType[n.id.name].set(path, t.exprName.name)
  }
})
if (byType.FileRoutesByFullPath.size === 0) error('the route tree lists no routes')
const idOfType = new Map([...byType.FileRoutesById].map(([id, t]) => [t, id]))

// 2. The server bundle: route registrations createFileRoute("ID")({ server: { handlers } }) and
// the server-function manifest { ID: { functionName, importer: () => import("./F") } }.
const files = (dir) =>
  readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
    e.isDirectory() && e.name !== 'node_modules' ? files(join(dir, e.name)) : e.isFile() && e.name.endsWith('.mjs') ? [join(dir, e.name)] : []
  )
const handlers = new Map() // route id -> sorted methods, or '-'
const fns = [] // { id, functionName, module }
for (const file of files(server)) {
  const src = readFileSync(file, 'utf8')
  if (!/createFileRoute|functionName|handlers/.test(src)) continue
  walk(parse(file, 'js'), (n) => {
    // handlers changed after registration (Route.options.server.handlers.X = ...)
    if (n.type === 'AssignmentExpression' && n.left.type === 'MemberExpression') {
      let m = n.left
      while (m?.type === 'MemberExpression') {
        const up = m.object.type === 'MemberExpression' && !m.object.computed ? m.object.property.name : null
        if (!m.computed && ((m.property.name === 'handlers' && up === 'server') || (m.property.name === 'server' && up === 'options')))
          error(`route handlers assigned after registration (${relative(server, file)})`)
        m = m.object
      }
    }
    if (n.type === 'CallExpression' && n.callee.type === 'CallExpression') {
      const c = n.callee
      const id = c.arguments.length === 1 ? str(c.arguments[0]) : null
      if (c.callee.type !== 'Identifier' || !c.callee.name.startsWith('createFileRoute') || id === null) return
      const opts = n.arguments[0]
      const srv = prop(opts, 'server')
      let methods = '-'
      if (srv) {
        const h = prop(srv.value, 'handlers')
        if (!h || h.value.type !== 'ObjectExpression' || h.value.properties.some((p) => p.type !== 'Property' || key(p) === null)) {
          error(`${id}: server handlers of another shape (${relative(server, file)})`)
          return
        }
        methods = h.value.properties.map(key).sort().join(',')
      }
      if (handlers.has(id) && handlers.get(id) !== methods) error(`${id}: registered twice`)
      handlers.set(id, methods)
    }
    if (n.type === 'ObjectExpression' && n.properties.length > 0) {
      const entries = n.properties.map((p) => {
        const fn = p.type === 'Property' && str(prop(p.value, 'functionName')?.value)
        const imp = p.type === 'Property' && prop(p.value, 'importer')?.value
        const target = imp?.type === 'ArrowFunctionExpression' && imp.body.type === 'ImportExpression' ? str(imp.body.source) : null
        return fn && target !== null ? { id: key(p), functionName: fn, module: join(dirname(file), target) } : null
      })
      if (entries.every(Boolean)) fns.push(...entries)
      else if (entries.some(Boolean)) error(`a server-function manifest with an entry of another shape (${relative(server, file)})`)
    }
  })
}

// 2b. The server's own router (SERVER/index.mjs): its route table findRoute must hold one
// route, /** to the lazily imported SSR renderer, answered by a function of a single return
// statement; its route rules findRouteRules may only set headers. Anything else — a server
// route, a handler, a proxy or redirect rule of the framework's own — is an error.
{
  const index = join(server, 'index.mjs')
  const decl = new Map()
  let ast
  try {
    ast = parse(index, 'js')
  } catch {
    error('the server entry index.mjs does not parse')
  }
  if (ast) walk(ast, (n) => n.type === 'VariableDeclarator' && n.id.type === 'Identifier' && decl.set(n.id.name, n.init))
  const renderer = (id) => {
    const init = id?.type === 'Identifier' ? decl.get(id.name) : null
    const f = init?.type === 'CallExpression' && init.callee.name === 'defineLazyEventHandler' ? init.arguments[0] : null
    return f?.type === 'ArrowFunctionExpression' && f.body.type === 'ImportExpression' && /\/ssr-renderer\.mjs$/.test(str(f.body.source) ?? '')
  }
  const routes = decl.get('findRoute')
  const rules = decl.get('findRouteRules')
  // the global middleware: the public-file handler and nothing else
  const mw = decl.get('globalMiddleware')
  const mwText = mw ? readFileSync(index, 'utf8').slice(mw.start, mw.end).replace(/\s+/g, '') : ''
  if (mwText !== '[toEventHandler(static_default)].filter(Boolean)') error(`the server's own global middleware is not the public-file handler alone: ${mwText}`)
  if (!routes || !rules) error('the server entry has no findRoute or no findRouteRules')
  else {
    const seen = []
    walk(routes, (n) => {
      if (n.type !== 'ObjectExpression') return
      const r = prop(n, 'route')
      if (r) seen.push(str(r.value) === '/**' && renderer(prop(n, 'handler')?.value) ? 'ok' : `${str(r.value)}`)
    })
    let fn = null
    walk(routes, (n) => (fn ??= n.type === 'ReturnStatement' && /FunctionExpression$/.test(n.argument?.type ?? '') ? n.argument : null))
    const single = fn?.body.type === 'BlockStatement' && fn.body.body.length === 1 && fn.body.body[0].type === 'ReturnStatement'
    if (seen.length !== 1 || seen[0] !== 'ok' || !single)
      error(`the server's own router serves more than /** to the renderer: ${seen.join(' ') || 'nothing'}`)
    walk(rules, (n) => {
      const name = n.type === 'ObjectExpression' && prop(n, 'name') ? str(prop(n, 'name').value) : 'headers'
      if (name !== 'headers') error(`a route rule of the server's own router that is not headers: ${name}`)
    })
  }
}

const ref = (path) => (path.split('/').includes('$ref') ? 'y' : 'n')
for (const [path, type] of byType.FileRoutesByFullPath) {
  const id = idOfType.get(type)
  if (id === undefined) {
    error(`${path}: no route id in the route tree`)
    continue
  }
  const kind = /^\/api\//.test(path) ? 'api' : 'page'
  let methods = handlers.get(id)
  if (methods === undefined) {
    // a page needs no registration of its own in the server bundle; an API route does
    if (kind === 'api') {
      error(`${path}: no registration in the server bundle`)
      continue
    }
    methods = '-'
  }
  out.push(`${kind}\t${path}\t${methods}\t${ref(path)}`)
}

// 3. Each server function's method: createServerFn({ method }).handler(FUNCTION_NAME, ...)
// in the module its manifest entry imports (no options: GET, the framework's default).
for (const f of fns) {
  let method = null
  try {
    walk(parse(f.module, 'js'), (n) => {
      if (n.type !== 'CallExpression' || n.callee.type !== 'MemberExpression' || n.callee.property.name !== 'handler') return
      if (n.arguments[0]?.type !== 'Identifier' || n.arguments[0].name !== f.functionName) return
      const create = n.callee.object
      if (create.type !== 'CallExpression') return
      const opts = create.arguments[0]
      if (opts === undefined) method = 'GET'
      else {
        const m = str(prop(opts, 'method')?.value)
        method = m ?? (prop(opts, 'method') ? null : 'GET')
      }
    })
  } catch (e) {
    error(`function ${f.id}: ${relative(server, f.module)} does not parse`)
    continue
  }
  if (method === null) error(`function ${f.id}: no method found for ${f.functionName} in ${relative(server, f.module)}`)
  else out.push(`function\t${f.id}\t${method.toUpperCase()}\tn`)
}

console.log([...new Set(out)].sort().join('\n'))
