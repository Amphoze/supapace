// SPDX-License-Identifier: Apache-2.0
//
// The browser harness's step interpreter. It reads one JSON scenario on
// standard input and writes one JSON result on standard output.
//
// Scenario: {"engine": "chromium"|"firefox"|"webkit", "hosts": {name: address},
// "ca": "/ca/ca.pem" (optional), "timeout_ms": n (optional), "script": false
// (optional: the engine runs no page script), "steps":
// [...]}.
// "hosts" is mapped by whoever starts the container (--add-host); this program
// gives every engine a proxy that does not exist (127.0.0.1:9) and bypasses it
// for exactly those names, so a name outside the map can be neither resolved
// nor reached. Before the browser starts, the CA
// named by "ca" is installed for the engine about to run: a fresh NSS database
// for Chromium ($HOME/.pki/nssdb) and Firefox (its profile), the system store
// for WebKit. Without "ca" the same stores are built without it. Certificate
// errors are never ignored.
//
// Steps ("tab" is an index, 0 when absent; newTab returns the next one):
//   goto     {tab, url}               → {url, status}   waits for the commit only
//   click    {tab, selector}
//   fill     {tab, selector, value}
//   wait     {tab, url | contains, text} → {url}        until the tab is at url (or a URL holding contains),
//                                                      loaded, and with text, until its body shows text
//   eval     {tab, expr}              → {value}         an expression in the page
//   eval     {tab, fetch: {url, init}} → {status, headers}
//   cookies  {}                       → {cookies: [{name, value, domain, path, expires, httpOnly, secure, sameSite}]}
//   setCookie {tab, cookie, name}     → {kept}          document.cookie = cookie; kept: a cookie of that name is in the jar
//                                                      once a mark the page wrote after it is (the mark is removed)
//   requests {}                       → {requests: [{tab, method, url, resourceType, initiator, site, referer, cookies}]} since the last call;
//                                                      site and referer are the Sec-Fetch-Site and Referer headers sent,
//                                                      cookies the names in the Cookie header sent
//   reload   {tab}                    reloads the tab (waits for the commit only)
//   drive    {tab, url}               → {url}           until the tab is at url, loaded, pressing the button of
//                                                      every page on the way that has one (a run without script)
//   newTab   {}                       → {tab}
//   pause    {ms}                     waits ms (to see that nothing follows)
//   clearCookies {prefix}             removes every cookie whose name starts with prefix
//
// Result: {"engine", "playwright", "resolv": [the nameserver lines of
// /etc/resolv.conf], "steps": [{op, ...}], "secure": {origin: bool},
// "error", and on an error "tabs" (each tab's URL) and "trail" (the requests
// not yet read)}. "secure" holds window.isSecureContext as every top-level document
// reported it at its start; a document that reports false fails the scenario.
// The first failing step carries "error" and ends the run; the result's
// "error" repeats it.

import { execFileSync } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { chromium, firefox, webkit } from 'playwright';

const engines = { chromium, firefox, webkit };
const home = '/tmp/home'; // the image's HOME, where Chromium reads its NSS database

function certutil(db, ca) {
  mkdirSync(db, { recursive: true, mode: 0o700 });
  execFileSync('certutil', ['-N', '-d', `sql:${db}`, '--empty-password'], { stdio: 'pipe' });
  if (ca) execFileSync('certutil', ['-A', '-d', `sql:${db}`, '-n', 'harness-ca', '-t', 'C,,', '-i', ca], { stdio: 'pipe' });
}

// trust builds the engine's store and returns the profile directory.
function trust(engine, ca) {
  mkdirSync(home, { recursive: true, mode: 0o700 });
  const profile = '/tmp/profile';
  mkdirSync(profile, { recursive: true, mode: 0o700 });
  if (engine === 'chromium') certutil(`${home}/.pki/nssdb`, ca);
  if (engine === 'firefox') certutil(profile, ca);
  if (engine === 'webkit') {
    mkdirSync('/tmp/trust', { recursive: true });
    let bundle = readFileSync('/opt/harness/system-ca.crt', 'utf8');
    if (ca) bundle += '\n' + readFileSync(ca, 'utf8');
    writeFileSync('/tmp/trust/ca-certificates.crt', bundle);
  }
  return profile;
}

async function main() {
  const sc = JSON.parse(readFileSync(0, 'utf8'));
  const pkg = JSON.parse(readFileSync('/opt/harness/node_modules/playwright/package.json', 'utf8'));
  // The nameserver lines the engines resolve with; whoever runs the container
  // checks them (only names mapped into /etc/hosts may resolve).
  const resolv = readFileSync('/etc/resolv.conf', 'utf8').split('\n').filter((l) => /^\s*nameserver\b/.test(l)).map((l) => l.trim());
  const out = { engine: sc.engine, playwright: pkg.version, resolv, steps: [], secure: {}, error: '' };
  const type = engines[sc.engine];
  if (!type) throw new Error(`unknown engine ${JSON.stringify(sc.engine)}`);
  const profile = trust(sc.engine, sc.ca);

  const ctx = await type.launchPersistentContext(profile, {
    headless: true,
    javaScriptEnabled: sc.script !== false,
    // Chromium also bypasses loopback and link-local literals unless told
    // not to (<-loopback>); the other engines do not know that token.
    proxy: {
      server: 'http://127.0.0.1:9',
      bypass: [...Object.keys(sc.hosts || {}), ...(sc.engine === 'chromium' ? ['<-loopback>'] : [])].join(','),
    },
  });
  ctx.setDefaultTimeout(sc.timeout_ms || 15000);
  const tabs = [];
  const seen = [];
  const insecure = [];
  await ctx.exposeBinding('__harnessSecure', (_src, origin, secure) => {
    if (out.secure[origin] !== false) out.secure[origin] = secure;
    if (!secure) insecure.push(origin);
  });
  await ctx.addInitScript(() => {
    // Top-level documents of a server; not the initial about:blank.
    if (window.top === window && /^https?:$/.test(location.protocol)) window.__harnessSecure(location.origin, window.isSecureContext);
  });
  const watch = (page) => {
    const tab = tabs.length;
    tabs.push(page);
    page.on('request', (r) => {
      let initiator = '';
      try {
        initiator = r.redirectedFrom()?.url() || r.frame().url();
      } catch {}
      const q = { tab, method: r.method(), url: r.url(), resourceType: r.resourceType(), initiator, site: '', referer: '', cookies: [] };
      seen.push(q);
      r.allHeaders().then((h) => {
        q.site = h['sec-fetch-site'] || '';
        q.referer = h['referer'] || '';
        q.cookies = (h['cookie'] || '').split(/;\s*/).filter(Boolean).map((c) => (c.includes('=') ? c.slice(0, c.indexOf('=')) : ''));
      }, () => {});
    });
    return tab;
  };
  watch(ctx.pages()[0] || (await ctx.newPage()));
  const tab = (s) => {
    const p = tabs[s.tab || 0];
    if (!p) throw new Error(`no tab ${s.tab}`);
    return p;
  };

  try {
    for (const s of sc.steps) {
      const r = { op: s.op };
      out.steps.push(r);
      try {
        switch (s.op) {
          case 'goto': {
            const resp = await tab(s).goto(s.url, { waitUntil: 'commit' });
            r.url = tab(s).url();
            r.status = resp ? resp.status() : 0;
            break;
          }
          case 'click':
            await tab(s).click(s.selector);
            break;
          case 'fill':
            await tab(s).fill(s.selector, s.value);
            break;
          case 'wait':
            await tab(s).waitForURL(s.contains ? (u) => u.href.includes(s.contains) : s.url, { waitUntil: 'load' });
            if (s.text) await tab(s).waitForFunction((t) => document.body && document.body.innerText.includes(t), s.text);
            r.url = tab(s).url();
            break;
          case 'eval':
            if (s.fetch) {
              Object.assign(r, await tab(s).evaluate(async ({ url, init }) => {
                const res = await fetch(url, init || {});
                return { status: res.status, headers: Object.fromEntries(res.headers.entries()) };
              }, s.fetch));
            } else {
              r.value = await tab(s).evaluate(s.expr);
            }
            break;
          case 'cookies':
            r.cookies = await ctx.cookies();
            break;
          case 'setCookie': {
            // A page's write reaches the jar the context reads later than the
            // page sees it (WebKit stores it in its network process). A page
            // has its writes stored in order, so a host-only mark written
            // after the cookie is waited for in the jar, then removed: when it
            // is there, so is the cookie, if the engine kept it.
            const mark = `sp_mark_${out.steps.length}`;
            await tab(s).evaluate(([c, m]) => { document.cookie = c; document.cookie = `${m}=1; Path=/; Secure`; }, [s.cookie, mark]);
            const end = Date.now() + (sc.timeout_ms || 15000);
            let jar;
            for (;;) {
              jar = await ctx.cookies();
              if (jar.some((c) => c.name === mark)) break;
              if (Date.now() > end) throw new Error('setCookie: the mark written after the cookie never reached the jar');
              await new Promise((ok) => setTimeout(ok, 20));
            }
            await ctx.clearCookies({ name: mark });
            r.kept = jar.some((c) => c.name === s.name);
            break;
          }
          case 'requests':
            r.requests = seen.splice(0);
            break;
          case 'pause':
            await new Promise((ok) => setTimeout(ok, s.ms));
            break;
          case 'clearCookies':
            await ctx.clearCookies({ name: new RegExp('^' + s.prefix.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')) });
            break;
          case 'drive': {
            const p = tab(s);
            const end = Date.now() + (sc.timeout_ms || 15000);
            for (;;) {
              await p.waitForLoadState('load');
              if (p.url() === s.url) break;
              if (Date.now() > end) throw new Error(`drive: still at ${p.url()}`);
              // A page may navigate on its own meanwhile (a refresh): a
              // destroyed context only means look again.
              const before = p.url();
              const b = await p.$('button').catch(() => null);
              if (b) await Promise.all([p.waitForURL((u) => u.href !== before, { waitUntil: 'commit' }).catch(() => {}), b.click().catch(() => {})]);
              else await p.waitForTimeout(100);
            }
            r.url = p.url();
            break;
          }
          case 'reload':
            await tab(s).reload({ waitUntil: 'commit' });
            break;
          case 'newTab':
            r.tab = watch(await ctx.newPage());
            break;
          default:
            throw new Error(`unknown step ${JSON.stringify(s.op)}`);
        }
        if (insecure.length) throw new Error(`not a secure context: ${insecure.join(' ')}`);
      } catch (e) {
        r.error = String(e && e.message ? e.message : e).split('\n')[0];
        out.error = `step ${out.steps.length - 1} (${s.op}): ${r.error}`;
        // Where every tab stands, and the requests not yet read: the trail
        // that makes the failing step exact.
        out.tabs = tabs.map((p) => p.url());
        out.trail = seen.splice(0);
        break;
      }
    }
  } finally {
    await ctx.close().catch(() => {});
  }
  process.stdout.write(JSON.stringify(out) + '\n');
}

main().catch((e) => {
  process.stdout.write(JSON.stringify({ steps: [], secure: {}, error: String(e && e.message ? e.message : e) }) + '\n');
  process.exitCode = 1;
});
