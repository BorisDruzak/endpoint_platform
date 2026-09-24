const test = require('node:test');
const assert = require('node:assert/strict');

const protocol = require('../protocol.js');

test('URL normalization strips path, query, fragment and credentials', () => {
  assert.deepEqual(protocol.normalizeUrl('https://user:password@Zakupki.Gov.Ru:443/private?q=secret#anchor'), {
    scheme: 'https', origin: 'https://zakupki.gov.ru', domain: 'zakupki.gov.ru',
  });
  for (const url of ['file:///private', 'chrome://settings', 'data:text/plain,secret', 'javascript:alert(1)']) {
    assert.equal(protocol.normalizeUrl(url), null);
  }
});

test('upload metadata excludes file names and values', () => {
  const secret = 'SECRET_MARKER_7348';
  const metadata = protocol.uploadMetadata([
    { name: `${secret}.xlsx`, size: 4096, type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' },
    { name: `${secret}.pdf`, size: 2048, type: 'application/pdf' },
  ]);
  assert.deepEqual(metadata, { file_count: 2, total_bytes: 6144, mime_categories: ['document', 'spreadsheet'] });
  assert.equal(JSON.stringify(metadata).includes(secret), false);
  assert.equal(protocol.uploadMetadata(Array.from({ length: 65 }, () => ({ size: 1, type: '' }))), null);
});

test('paste metadata captures coarse types, never clipboard content', () => {
  const secret = 'SECRET_MARKER_7348';
  const types = ['text/plain', 'text/html', `application/x-${secret}`, 'image/png'];
  const metadata = protocol.pasteMetadata(types);
  assert.deepEqual(metadata, { clipboard_types: ['html', 'image', 'other', 'text'] });
  assert.equal(JSON.stringify(metadata).includes(secret), false);
});

test('family detection distinguishes Yandex from Chrome', () => {
  assert.equal(protocol.browserFamily('Mozilla/5.0 Chrome/130.0 YaBrowser/24.0'), 'yandex');
  assert.equal(protocol.browserFamily('Mozilla/5.0 Chrome/130.0 Safari/537.36'), 'chrome');
  assert.equal(protocol.browserFamily('Mozilla/5.0 Chrome/130.0 Edg/130.0'), null);
});

test('native messages have a strict 16 KiB UTF-8 bound', () => {
  assert.equal(protocol.withinMessageLimit({ kind: 'heartbeat', value: 'ok' }), true);
  assert.equal(protocol.withinMessageLimit({ value: 'é'.repeat(9000) }), false);
});
