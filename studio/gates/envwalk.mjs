// SPDX-License-Identifier: Apache-2.0
// envwalk.mjs PARSER ROOT — every read of the process environment in the JavaScript files under
// ROOT (.js, .mjs, .cjs), found by walking each file's syntax tree with the bundler's own parser
// (PARSER/node_modules/rolldown, exported by the build). Prints, sorted, one line per finding:
//   read<TAB>NAME<TAB>FILE                  a name read by one of the accepted forms
//   unresolved<TAB>FILE<TAB>LINE: WHAT      a read that cannot be resolved to a name
// FILE is relative to ROOT, with a bundler's content hash (-XXXXXXXX.mjs) written -[hash].mjs.
// The accepted forms, on process.env and on import.meta.env alike: a member access by name
// (env.NAME), a computed access with a literal (env["NAME"]) or with a name the file binds once
// and only ever sets to one string literal (var K = "NAME"; a for-of or for-in loop variable is
// not such a name); a destructuring with such keys (const { NAME } = env); and `"NAME" in env`.
// Anything else that touches the environment object is unresolved: a computed access by
// anything else, a rest element, the object passed, assigned, spread or returned as a whole.
// The process object itself may be read by a member of a resolved name (process.argv),
// compared, negated or tested; a computed member that does not resolve, or the object passed,
// assigned or returned as a whole, is unresolved, unless the name `process` is a binding of the
// enclosing function or catch clause. `process` is also reached as globalThis.process (global,
// self, window), through an import, a dynamic import, a require, a created require or the
// built-in module getter of "process" or "node:process" (any one-argument call with that
// literal), and `env` through such an import's named binding. A computed access on a global
// object (one the file does not bind itself) whose key does not resolve and is no Symbol, and a
// built-in module getter called with a non-literal, are unresolved. A file that does not parse
// is unresolved.
// Limit: code compiled at run time (new Function, eval of a string) is outside any syntax walk;
// the walk sees the bundle as written.
import { readFileSync, readdirSync } from 'node:fs'
import { createRequire } from 'node:module'
import { join, relative } from 'node:path'
import { pathToFileURL } from 'node:url'

const [parserDir, root] = process.argv.slice(2)
if (!parserDir || !root) {
  console.error('usage: envwalk.mjs PARSER ROOT')
  process.exit(2)
}
const { parseAst } = await import(
  pathToFileURL(createRequire(join(parserDir, 'x.js')).resolve('rolldown/parseAst')).href
)

const PROCESS_MODULES = new Set(['process', 'node:process'])
const GLOBALS = ['globalThis', 'global', 'self', 'window']
const FUNCTION = /^(FunctionDeclaration|FunctionExpression|ArrowFunctionExpression)$/
const out = []

function files(dir) {
  const r = []
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, e.name)
    if (e.isDirectory()) r.push(...files(p))
    else if (e.isFile() && /\.(m|c)?js$/.test(e.name)) r.push(p)
  }
  return r
}

// visit(node, fn): fn(node, parents) for every node, parents innermost last; fn returning
// false skips the node's children
function visit(node, fn, parents = []) {
  if (fn(node, parents) === false) return
  parents.push(node)
  for (const k in node) {
    if (k === 'type' || k === 'start' || k === 'end') continue
    const v = node[k]
    if (Array.isArray(v)) {
      for (const c of v) if (c && typeof c.type === 'string') visit(c, fn, parents)
    } else if (v && typeof v.type === 'string') visit(v, fn, parents)
  }
  parents.pop()
}

// the identifiers a binding pattern binds
function bound(p, acc = []) {
  if (!p) return acc
  if (p.type === 'Identifier') acc.push(p)
  else if (p.type === 'AssignmentPattern') bound(p.left, acc)
  else if (p.type === 'RestElement') bound(p.argument, acc)
  else if (p.type === 'ArrayPattern') p.elements.forEach((e) => bound(e, acc))
  else if (p.type === 'ObjectPattern') p.properties.forEach((q) => bound(q.type === 'RestElement' ? q : q.value, acc))
  return acc
}

const literal = (n) => {
  if (n?.type === 'Literal' && typeof n.value === 'string') return n.value
  if (n?.type === 'TemplateLiteral' && n.expressions.length === 0) return n.quasis[0].value.cooked
  return null
}

for (const file of files(root).sort()) {
  const rel = relative(root, file).replace(/-([A-Za-z0-9_-]{8})\.mjs$/, (m, h) => (/[A-Z0-9_]/.test(h) ? '-[hash].mjs' : m))
  const src = readFileSync(file, 'utf8')
  const line = (pos) => src.slice(0, pos).split('\n').length
  const unresolved = (node, what) => out.push(`unresolved\t${rel}\t${line(node.start)}: ${what}`)
  let ast
  try {
    ast = parseAst(src, { sourceType: 'unambiguous', preserveParens: false }, file)
  } catch (e) {
    out.push(`unresolved\t${rel}\t0: does not parse: ${String(e.message).split('\n')[0]}`)
    continue
  }

  // One pass for the file's bindings: how often each name is bound, the string constants, the
  // functions and catch clauses that bind their own `process`, and the local names of an import
  // of the process module.
  const count = new Map()
  const writes = new Map() // name -> the values written to it (null: not a string literal)
  const write = (name, v) => writes.set(name, [...(writes.get(name) ?? []), v])
  const shadows = [] // [start, end]
  const procIds = new Set()
  const envIds = new Set()
  const bind = (id) => count.set(id.name, (count.get(id.name) ?? 0) + 1)
  visit(ast, (n, parents) => {
    const parent = parents[parents.length - 1]
    if (n.type === 'VariableDeclarator') {
      const ids = bound(n.id)
      ids.forEach(bind)
      if (n.init) ids.forEach((i) => write(i.name, n.id.type === 'Identifier' ? literal(n.init) : null))
      if (ids.some((i) => i.name === 'process')) {
        const scope = [...parents].reverse().find((p) => FUNCTION.test(p.type) || p.type === 'Program')
        shadows.push([scope.start, scope.end])
      }
    } else if (FUNCTION.test(n.type)) {
      const ids = n.params.flatMap((p) => bound(p))
      if (n.id) bind(n.id)
      ids.forEach(bind)
      if (ids.some((i) => i.name === 'process') || (n.type === 'FunctionExpression' && n.id?.name === 'process'))
        shadows.push([n.start, n.end])
    } else if (n.type === 'CatchClause' && n.param) {
      const ids = bound(n.param)
      ids.forEach(bind)
      if (ids.some((i) => i.name === 'process')) shadows.push([n.start, n.end])
    } else if (n.type === 'AssignmentExpression') {
      if (n.left.type === 'Identifier') write(n.left.name, n.operator === '=' ? literal(n.right) : null)
      else bound(n.left).forEach((i) => write(i.name, null))
    } else if (n.type === 'UpdateExpression' && n.argument.type === 'Identifier') {
      write(n.argument.name, null)
    } else if (n.type === 'ForOfStatement' || n.type === 'ForInStatement') {
      // the loop variable is written by each iteration, whatever it was initialised to
      bound(n.left.type === 'VariableDeclaration' ? n.left.declarations[0].id : n.left).forEach((i) => write(i.name, null))
    } else if (n.type === 'ClassDeclaration' && n.id) {
      bind(n.id)
    } else if (n.type === 'ImportDeclaration') {
      for (const sp of n.specifiers) {
        bind(sp.local)
        if (!PROCESS_MODULES.has(n.source.value)) continue
        const imported = sp.type === 'ImportSpecifier' ? (sp.imported.name ?? sp.imported.value) : 'default'
        if (imported === 'env') envIds.add(sp.local.name)
        else if (imported === 'default' || sp.type === 'ImportNamespaceSpecifier') procIds.add(sp.local.name)
      }
    }
  })
  // a string constant: a name bound once, and only ever given one string literal
  const constants = new Map()
  for (const [name, vs] of writes)
    if (count.get(name) === 1 && vs.every((v) => v !== null && v === vs[0])) constants.set(name, vs[0])
  const shadowed = (n) => shadows.some(([s, e]) => n.start >= s && n.start < e)

  // the name a member access or a key names, or null when it cannot be resolved
  const keyName = (computed, key) => {
    if (!computed) return key.type === 'Identifier' ? key.name : literal(key)
    if (key.type === 'Identifier') return constants.get(key.name) ?? null
    return literal(key)
  }
  // an identifier that is a property's or a member's name, not a reference to a binding
  const isName = (n, p) =>
    n.type === 'Identifier' &&
    !!p &&
    ((p.type === 'MemberExpression' && p.property === n && !p.computed) ||
      (/^(Property|MethodDefinition|PropertyDefinition)$/.test(p.type) && p.key === n && !p.computed && !p.shorthand) ||
      /^Import(Default|Namespace)?Specifier$/.test(p.type))
  const isProcess = (n) => {
    if (n.type === 'Identifier') return n.name === 'process' || procIds.has(n.name)
    if (n.type === 'AwaitExpression') return isProcess(n.argument)
    // import("process"); a call of any require-like function (require, a created require,
    // getBuiltinModule) with the literal "process" or "node:process"
    if (n.type === 'ImportExpression') return PROCESS_MODULES.has(literal(n.source))
    if (n.type === 'CallExpression') return n.arguments.length === 1 && PROCESS_MODULES.has(literal(n.arguments[0]))
    return (
      n.type === 'MemberExpression' &&
      n.object.type === 'Identifier' &&
      GLOBALS.includes(n.object.name) &&
      keyName(n.computed, n.property) === 'process'
    )
  }
  const isEnv = (n, parent) => {
    if (n.type === 'Identifier') return envIds.has(n.name) && !isName(n, parent)
    if (n.type !== 'MemberExpression' || keyName(n.computed, n.property) !== 'env') return false
    if (n.object.type === 'MetaProperty') return n.object.meta.name === 'import' && n.object.property.name === 'meta'
    // X.process.env, whatever X is (an alias of the global object, a ternary, a getter):
    // the name process holds the process object in the forms libraries use
    return isProcess(n.object) || (n.object.type === 'MemberExpression' && keyName(n.object.computed, n.object.property) === 'process')
  }
  // the parent of node, looking through a ChainExpression; and the child that parent holds
  const up = (node, parents) => {
    let i = parents.length - 1
    let child = node
    while (i >= 0 && parents[i].type === 'ChainExpression') child = parents[i--]
    return [parents[i], child]
  }
  // the names of a destructuring pattern; a rest element or an unresolved key is unresolved
  const pattern = (p) => {
    for (const prop of p.properties) {
      const name = prop.type === 'Property' ? keyName(prop.computed, prop.key) : null
      if (name === null) unresolved(prop, `destructuring with ${prop.type === 'RestElement' ? 'a rest element' : 'a computed key'}`)
      else out.push(`read\t${name}\t${rel}`)
    }
  }

  visit(ast, (node, parents) => {
    const parent = parents[parents.length - 1]
    // a computed access on a global object, or a module getter's argument, that does not
    // resolve to a literal could name the process object
    // (a name the file binds itself, as `var self = this`, is not the global; a Symbol key is
    // no name)
    const symbol = (k) => (k.type === 'CallExpression' ? k.callee : k).object?.name === 'Symbol'
    if (node.type === 'MemberExpression' && node.computed && node.object.type === 'Identifier' &&
        GLOBALS.includes(node.object.name) && !count.has(node.object.name) &&
        keyName(true, node.property) === null && !symbol(node.property))
      unresolved(node, 'a computed access on the global object that is not a literal')
    if (node.type === 'CallExpression' && node.callee.type === 'MemberExpression' &&
        keyName(node.callee.computed, node.callee.property) === 'getBuiltinModule' && literal(node.arguments[0]) === null)
      unresolved(node, 'a built-in module getter with an argument that is not a literal')
    if (isEnv(node, parent)) {
      const [p, child] = up(node, parents)
      if (p?.type === 'MemberExpression' && p.object === child) {
        const name = keyName(p.computed, p.property)
        if (name === null) unresolved(p, 'a computed access that is not a literal')
        else out.push(`read\t${name}\t${rel}`)
      } else if (p?.type === 'VariableDeclarator' && p.init === child && p.id.type === 'ObjectPattern') {
        pattern(p.id)
      } else if (p?.type === 'AssignmentExpression' && p.right === child && p.left.type === 'ObjectPattern') {
        pattern(p.left)
      } else if (p?.type === 'BinaryExpression' && p.operator === 'in' && p.right === child && literal(p.left) !== null) {
        out.push(`read\t${literal(p.left)}\t${rel}`)
      } else {
        unresolved(node, `the environment object used as a whole (in ${p?.type ?? 'the program'})`)
      }
      return false // nothing inside process.env / import.meta.env to walk
    }
    if (isProcess(node) && !isName(node, parent) && !(node.type === 'Identifier' && shadowed(node))) {
      const [p, child] = up(node, parents)
      const ok =
        (p.type === 'MemberExpression' && p.object === child && keyName(p.computed, p.property) !== null) ||
        (p.type === 'UnaryExpression' && (p.operator === 'typeof' || p.operator === '!')) ||
        (p.type === 'BinaryExpression' && /^[!=]==?$/.test(p.operator)) ||
        (p.type === 'LogicalExpression' && p.operator === '&&' && p.left === child) ||
        (/^(ConditionalExpression|IfStatement)$/.test(p.type) && p.test === child)
      if (!ok) unresolved(node, `the process object used as a whole (in ${p.type})`)
      if (node.type === 'Identifier') return false
    }
  })
}

console.log([...new Set(out)].sort().join('\n'))
