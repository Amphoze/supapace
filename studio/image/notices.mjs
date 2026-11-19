// notices.mjs — reads `pnpm --filter "studio..." list --depth Infinity --json` on stdin and
// writes the licence notices of every dependency of the dashboard and its workspace packages,
// dev ones included (a superset of what the server bundle includes): per package its name,
// version, declared licence and the text of its licence and notice files. Run by
// studio/build.sh in the build container.
import fs from 'node:fs'
import path from 'node:path'

const roots = JSON.parse(fs.readFileSync(0, 'utf8'))
const byPath = new Map()
const kinds = ['dependencies', 'devDependencies', 'optionalDependencies']
// pnpm prints a package's dependencies once and marks its other occurrences "deduped"
// (without them): a package is walked at its one full occurrence, wherever that is
const walked = new Set()
const walk = (node) => {
  for (const k of kinds) {
    for (const d of Object.values(node[k] ?? {})) {
      if (!d.path) continue
      if (!byPath.has(d.path)) byPath.set(d.path, d)
      if (d.deduped || walked.has(d.path)) continue
      walked.add(d.path)
      walk(d)
    }
  }
}
for (const r of roots) walk(r)

const out = [
  'Licence notices of the third-party packages the dashboard server is built from.',
  `Packages: ${byPath.size}.`,
  '',
]
for (const p of [...byPath.keys()].sort()) {
  let pkg = {}
  try {
    pkg = JSON.parse(fs.readFileSync(path.join(p, 'package.json'), 'utf8'))
  } catch {}
  const name = pkg.name ?? byPath.get(p).from
  const licence = typeof pkg.license === 'string' ? pkg.license : JSON.stringify(pkg.license ?? pkg.licenses ?? 'UNKNOWN')
  out.push('='.repeat(72), `${name} ${pkg.version ?? byPath.get(p).version ?? ''} — ${licence}`, '')
  let files = []
  try {
    files = fs.readdirSync(p).filter((f) => /^(licen[cs]e|copying|notice)/i.test(f)).sort()
  } catch {}
  for (const f of files) {
    const full = path.join(p, f)
    if (fs.statSync(full).isFile()) out.push(fs.readFileSync(full, 'utf8').trimEnd(), '')
  }
  if (files.length === 0) out.push('(no licence file in the package; its declared licence is above)', '')
}
process.stdout.write(out.join('\n') + '\n')
