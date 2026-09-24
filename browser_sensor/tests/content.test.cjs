const test = require('node:test');
const assert = require('node:assert/strict');

const { createContentSensor } = require('../content.js');
const protocol = require('../protocol.js');

test('content script forwards only upload and paste metadata', () => {
  const handlers = new Map();
  const documentRef = { addEventListener: (name, handler) => handlers.set(name, handler) };
  const sent = [];
  const runtime = { sendMessage: (message) => { sent.push(message); return Promise.resolve(); } };
  createContentSensor(documentRef, runtime, protocol);
  const secret = 'SECRET_MARKER_7348';
  handlers.get('change')({ target: { tagName: 'INPUT', type: 'file', files: [
    { name: `${secret}.xlsx`, size: 16, type: 'application/vnd.ms-excel' },
  ], value: `C:\\Users\\${secret}.xlsx` } });
  handlers.get('paste')({ clipboardData: {
    types: ['text/plain', 'text/html'],
    getData: () => { throw new Error('clipboard content read'); },
  } });
  handlers.get('paste')({ isTrusted: false, clipboardData: { types: ['text/plain'] } });
  assert.equal(sent.length, 2);
  assert.equal(sent[0].kind, 'upload');
  assert.equal(sent[1].kind, 'paste');
  assert.equal(JSON.stringify(sent).includes(secret), false);
});
