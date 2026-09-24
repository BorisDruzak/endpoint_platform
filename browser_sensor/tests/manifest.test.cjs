const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

test('one MV3 manifest has only approved permissions and no remote code', () => {
  const root = path.join(__dirname, '..');
  const manifest = JSON.parse(fs.readFileSync(path.join(root, 'manifest.json'), 'utf8'));
  assert.equal(manifest.manifest_version, 3);
  assert.deepEqual([...manifest.permissions].sort(), ['alarms', 'nativeMessaging', 'tabs']);
  assert.equal(manifest.background.service_worker, 'background.js');
  assert.deepEqual(manifest.content_scripts[0].matches.sort(), ['http://*/*', 'https://*/*']);
  assert.deepEqual(manifest.content_scripts[0].js, ['protocol.js', 'content.js']);
  assert.equal(manifest.host_permissions, undefined);
  assert.equal(manifest.externally_connectable, undefined);
  assert.equal(manifest.content_security_policy, undefined);
  for (const name of ['background.js', 'content.js', 'protocol.js']) {
    const source = fs.readFileSync(path.join(root, name), 'utf8');
    assert.doesNotMatch(source, /\b(?:fetch|XMLHttpRequest|WebSocket|eval|Function)\s*\(/);
    assert.doesNotMatch(source, /clipboard(?:Read|Write)|\.getData\s*\(/);
  }
});
