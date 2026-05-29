"use strict";
/*
 * Test fixture that mimics the *shape* of a live Express app's internal router
 * stack (app._router.stack) without requiring the `express` package, so the
 * runtime introspector can be exercised in CI without an npm install.
 *
 * Crucially it includes routes generated in a loop — exactly the kind of
 * dynamically-registered endpoints that static source parsing cannot see.
 */

function routeLayer(p, methods, handlerNames) {
  return { route: { path: p, methods, stack: handlerNames.map((n) => ({ name: n })) } };
}

const apiStack = [
  routeLayer("/secure", { get: true }, ["requireAuth", "<anonymous>"]),
  routeLayer("/open", { post: true }, ["<anonymous>"]),
];

// Dynamically generated routes (a loop a static parser would miss).
for (const resource of ["orders", "invoices"]) {
  apiStack.push(routeLayer("/" + resource + "/:id", { get: true }, ["<anonymous>"]));
}

const app = {};
app._router = {
  stack: [
    { name: "helmet", handle: function helmet() {} }, // global, non-auth middleware
    routeLayer("/health", { get: true }, ["<anonymous>"]),
    {
      name: "router",
      regexp: /^\/api\/?(?=\/|$)/i, // router mounted at /api
      handle: { stack: apiStack },
    },
  ],
};

module.exports = app;
