const test = require('node:test');
const assert = require('node:assert/strict');

const { createBrowserSensorRuntime } = require('../background.js');

function signal() {
  const listeners = [];
  return { addListener: (listener) => listeners.push(listener), fire: (...args) => listeners.forEach((listener) => listener(...args)) };
}

function harness(queryTabs = async () => [], getSelf = null) {
  const sent = [];
  const ports = [];
  const alarms = [];
  const timeouts = [];
  const events = { activated: signal(), updated: signal(), alarm: signal(), startup: signal(), installed: signal(), message: signal() };
  const chromeApi = {
    runtime: {
      id: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      getManifest: () => ({ version: '0.1.0' }),
      connectNative: (name) => {
        const port = { name, postMessage: (message) => sent.push(message), onDisconnect: signal(), onMessage: signal() };
        ports.push(port);
        return port;
      },
      onStartup: events.startup, onInstalled: events.installed, onMessage: events.message,
    },
    tabs: { onActivated: events.activated, onUpdated: events.updated,
      get: async () => ({ active: true, url: 'https://example.test/private?secret=1' }),
      query: queryTabs,
    },
    alarms: { create: (...args) => alarms.push(args), onAlarm: events.alarm },
  };
  if (getSelf) chromeApi.management = { getSelf };
  createBrowserSensorRuntime(chromeApi, {
    userAgent: 'Chrome/130.0 YaBrowser/24.0',
    now: () => new Date('2026-09-25T10:00:00Z'),
    uuid: () => '00000000-0000-4000-8000-000000000001',
    schedule: (fn, delay) => timeouts.push({ fn, delay }),
  });
  return { sent, ports, alarms, timeouts, events };
}

test('worker reports only its own administrative install type without management permission', async () => {
  const value = harness(async () => [], async () => ({
    id: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', installType: 'admin',
    name: 'Must not leave browser', permissions: ['secret'],
  }));
  await new Promise((resolve) => setImmediate(resolve));
  const heartbeats = value.sent.filter((item) => item.schema_version === 'browser_sensor_heartbeat_v1');
  assert.equal(heartbeats.at(-1).install_type, 'admin');
  assert.equal(JSON.stringify(value.sent).includes('Must not leave browser'), false);
  assert.equal(JSON.stringify(value.sent).includes('secret'), false);
});

test('worker keeps install type unknown when self inspection is unavailable or mismatched', async () => {
  const unavailable = harness();
  const mismatched = harness(async () => [], async () => ({
    id: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', installType: 'admin',
  }));
  const rejected = harness(async () => [], async () => { throw new Error('unavailable'); });
  await new Promise((resolve) => setImmediate(resolve));
  for (const value of [unavailable, mismatched, rejected]) {
    const heartbeat = value.sent.find((item) => item.schema_version === 'browser_sensor_heartbeat_v1');
    assert.equal(heartbeat.install_type, 'unknown');
    assert.equal(value.sent.some((item) => item.install_type === 'admin'), false);
  }
});

test('worker sends hello, normalized active origin and heartbeat only to native host', async () => {
  const value = harness();
  assert.equal(value.ports[0].name, 'ru.sosnadmin.endpoint.browser');
  assert.equal(value.sent[0].schema_version, 'browser_sensor_hello_v1');
  assert.equal(value.sent[0].browser_family, 'yandex');
  value.events.activated.fire({ tabId: 7 });
  await new Promise((resolve) => setImmediate(resolve));
  const context = value.sent.find((item) => item.schema_version === 'browser_sensor_context_v1');
  assert.equal(context.origin, 'https://example.test');
  assert.equal(JSON.stringify(context).includes('secret'), false);
  value.events.alarm.fire({ name: 'endpoint-browser-heartbeat' });
  assert.equal(value.sent.at(-1).schema_version, 'browser_sensor_heartbeat_v1');
  assert.deepEqual(value.alarms[0], ['endpoint-browser-heartbeat', { periodInMinutes: 1 }]);
});

test('worker validates content metadata and reconnects with bounded queue', () => {
  const value = harness();
  value.ports[0].onDisconnect.fire();
  const secret = 'SECRET_MARKER_7348';
  value.events.message.fire({ schema_version: 'browser_content_event_v1', kind: 'upload',
    metadata: { file_count: 1, total_bytes: 123, mime_categories: ['document'] } },
  { id: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', tab: { active: true, url: `https://example.test/${secret}?q=${secret}` } });
  value.events.message.fire({ schema_version: 'browser_content_event_v1', kind: 'paste',
    metadata: { clipboard_types: ['text'], value: secret } },
  { id: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', tab: { active: true, url: 'https://example.test/' } });
  assert.equal(value.timeouts.length, 1);
  value.timeouts[0].fn();
  assert.equal(value.ports.length, 2);
  assert.equal(value.sent.filter((item) => item.event_type === 'BROWSER_UPLOAD').length, 1);
  assert.equal(JSON.stringify(value.sent).includes(secret), false);
});

test('heartbeat refreshes active-tab context without sending URL path', async () => {
  const value = harness(async () => [{ active: true, url: 'https://example.test/secret?q=secret' }]);
  await new Promise((resolve) => setImmediate(resolve));
  const before = value.sent.filter((item) => item.schema_version === 'browser_sensor_context_v1').length;
  value.events.alarm.fire({ name: 'endpoint-browser-heartbeat' });
  await new Promise((resolve) => setImmediate(resolve));
  const contexts = value.sent.filter((item) => item.schema_version === 'browser_sensor_context_v1');
  assert.equal(contexts.length, before + 1);
  assert.equal(contexts.at(-1).origin, 'https://example.test');
  assert.equal(JSON.stringify(contexts).includes('secret'), false);
});
