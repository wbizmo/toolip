// Test-only preload: makes process.versions.node report TOOLIP_TEST_NODE_VERSION
// so the real CLI entry point can be exercised on a simulated unpatched runtime.
const fake = process.env.TOOLIP_TEST_NODE_VERSION;
if (fake) {
  Object.defineProperty(process.versions, 'node', {
    value: fake,
    configurable: true
  });
}
