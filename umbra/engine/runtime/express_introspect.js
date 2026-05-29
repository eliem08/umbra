#!/usr/bin/env node
/*
 * Express runtime introspector.
 *
 * Usage:  node express_introspect.js <app-entry.js>
 *
 * Loads the Express application exported by the entry module and walks its live
 * router stack (`app._router.stack` on Express 4, `app.router.stack` on
 * Express 5). Because routes are enumerated from the *actual* registered stack,
 * this discovers dynamically-registered routes that static source parsing
 * cannot see (loops, conditional mounts, routes added by plugins, etc.).
 *
 * Output: a JSON object on stdout:
 *   { "routes": [ { "path": "/api/x", "method": "GET", "middleware": [...] } ] }
 *
 * SAFETY: requiring the entry executes the app's module-load code. Only run
 * this against codebases you trust.
 */
"use strict";

const path = require("path");

// Express/Connect internal middleware names we never want to treat as user auth.
const IGNORED_MW = new Set([
  "<anonymous>", "bound dispatch", "expressInit", "query",
  "serveStatic", "jsonParser", "urlencodedParser", "router", "handle",
]);

function fail(message) {
  process.stdout.write(JSON.stringify({ error: message }));
  process.exit(2);
}

function loadApp(entry) {
  let mod;
  try {
    mod = require(path.resolve(entry));
  } catch (e) {
    fail("Failed to require app entry '" + entry + "': " + (e && e.message ? e.message : String(e)));
  }
  const candidates = [mod, mod && mod.app, mod && mod.default, mod && mod.server, mod && mod.application];
  for (const c of candidates) {
    if (c && (c._router || (c.router && c.router.stack))) return c;
  }
  // express() instances are functions; some apps export the app function directly.
  for (const c of candidates) {
    if (typeof c === "function" && (c._router || c.router)) return c;
  }
  fail("Could not locate an Express app export. Export the app via `module.exports = app` or `{ app }`.");
}

function routerStack(app) {
  const router = app._router || app.router;
  return router && Array.isArray(router.stack) ? router.stack : [];
}

// Reconstruct a mount prefix from a layer's path-to-regexp source.
function mountPath(layer) {
  if (!layer.regexp) return "";
  if (layer.regexp.fast_slash) return ""; // mounted at '/'
  let p = layer.regexp.source;
  p = p.replace(/^\^/, "").replace(/\$$/, "");
  // Strip path-to-regexp's trailing optional-slash lookahead: \/?(?=\/|$)
  p = p.replace(/\\\/\?\(\?=\\\/\|\$\)/g, "");
  p = p.replace(/\(\?=\\\/\|\$\)/g, "");
  p = p.replace(/\\\/\?$/, "");
  p = p.replace(/\\\//g, "/"); // \/ -> /
  return p;
}

function joinPath(a, b) {
  let s = (a || "") + (b || "");
  s = s.replace(/\/{2,}/g, "/");
  if (!s.startsWith("/")) s = "/" + s;
  if (s.length > 1 && s.endsWith("/")) s = s.slice(0, -1);
  return s;
}

function methodsOf(route) {
  const m = route.methods || {};
  return Object.keys(m).filter((k) => m[k]).map((k) => k.toUpperCase());
}

function cleanNames(names) {
  return names.filter((n) => n && !IGNORED_MW.has(n));
}

function walk(stack, prefix, inherited, out) {
  // `inherited` = middleware function names registered (via .use) before the
  // current point in THIS stack; they apply to subsequent routes in the stack.
  const local = inherited.slice();
  for (const layer of stack) {
    if (layer.route) {
      const route = layer.route;
      const routeMw = cleanNames((route.stack || []).map((l) => l.name));
      const middleware = Array.from(new Set(local.concat(routeMw)));
      for (const method of methodsOf(route)) {
        out.push({ path: joinPath(prefix, route.path), method, middleware });
      }
    } else if (layer.handle && Array.isArray(layer.handle.stack)) {
      // Mounted sub-router: recurse with combined prefix and a copy of inherited mw.
      walk(layer.handle.stack, joinPath(prefix, mountPath(layer)), local.slice(), out);
    } else if (typeof layer.handle === "function" || layer.name) {
      // Plain middleware registered with .use(fn) — applies to later routes here.
      const name = layer.name;
      if (name && !IGNORED_MW.has(name)) local.push(name);
    }
  }
}

function main() {
  const entry = process.argv[2];
  if (!entry) fail("No app entry path provided.");
  const app = loadApp(entry);
  const out = [];
  try {
    walk(routerStack(app), "", [], out);
  } catch (e) {
    fail("Failed to walk router stack: " + (e && e.message ? e.message : String(e)));
  }
  process.stdout.write(JSON.stringify({ routes: out }));
  // Force exit so a live app.listen() server does not keep the process alive.
  process.exit(0);
}

main();
