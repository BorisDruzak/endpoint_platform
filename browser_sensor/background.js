/* The only extension-to-Agent route is the fixed local Native Messaging host. */
if (typeof importScripts === 'function') importScripts('protocol.js');

(function (root) {
  'use strict';

  const protocol = root.EndpointSensorProtocol || (typeof module === 'object' && module.exports ? require('./protocol.js') : null);
  const HOST = 'ru.sosnadmin.endpoint.browser';
  const ALARM = 'endpoint-browser-heartbeat';
  const PROTOCOL_VERSION = 1;
  const MAX_QUEUE = 64;

  function createBrowserSensorRuntime(api, options = {}) {
    const family = protocol.browserFamily(options.userAgent || root.navigator.userAgent);
    const version = api.runtime.getManifest().version;
    const now = options.now || (() => new Date());
    const uuid = options.uuid || (() => root.crypto.randomUUID());
    const schedule = options.schedule || ((callback, delay) => setTimeout(callback, delay));
    const queue = [];
    let port = null;
    let reconnectScheduled = false;
    let reconnectDelay = 1000;

    function observedAt() { return now().toISOString(); }

    function post(message) {
      if (!family || !protocol.withinMessageLimit(message)) return false;
      if (port) {
        try {
          port.postMessage(message);
          return true;
        } catch (_) {
          port = null;
          scheduleReconnect();
        }
      }
      if (queue.length === MAX_QUEUE) queue.shift();
      queue.push(message);
      return false;
    }

    function scheduleReconnect() {
      if (reconnectScheduled) return;
      reconnectScheduled = true;
      schedule(() => {
        reconnectScheduled = false;
        connect();
      }, reconnectDelay);
      reconnectDelay = Math.min(reconnectDelay * 2, 60000);
    }

    function connect() {
      if (!family || port) return;
      try {
        const connected = api.runtime.connectNative(HOST);
        port = connected;
        connected.onDisconnect.addListener(() => {
          if (port === connected) port = null;
          scheduleReconnect();
        });
        connected.onMessage.addListener((reply) => {
          if (reply && reply.schema_version === 'browser_bridge_ack_v1') reconnectDelay = 1000;
        });
        post({
          schema_version: 'browser_sensor_hello_v1', protocol_version: PROTOCOL_VERSION,
          extension_id: api.runtime.id, extension_version: version,
          browser_family: family, observed_at: observedAt(),
        });
        while (queue.length && port === connected) {
          const message = queue.shift();
          post(message);
        }
      } catch (_) {
        port = null;
        scheduleReconnect();
      }
    }

    function heartbeat() {
      post({
        schema_version: 'browser_sensor_heartbeat_v1', protocol_version: PROTOCOL_VERSION,
        extension_version: version, browser_family: family, observed_at: observedAt(),
      });
    }

    function reportTab(tab) {
      if (!tab || !tab.active) return;
      const context = protocol.normalizeUrl(tab.url);
      if (!context) return;
      post({
        schema_version: 'browser_sensor_context_v1', protocol_version: PROTOCOL_VERSION,
        browser_family: family, ...context, tab_active: true, observed_at: observedAt(),
      });
    }

    async function reportCurrentTab() {
      try {
        const tabs = await api.tabs.query({ active: true, currentWindow: true });
        if (tabs.length) reportTab(tabs[0]);
      } catch (_) { /* Tab inspection is optional while no browser window exists. */ }
    }

    function onContentMessage(message, sender) {
      if (!message || typeof message !== 'object' || !protocol.withinMessageLimit(message)
          || Object.keys(message).some((key) => !['schema_version', 'kind', 'metadata'].includes(key))
          || message.schema_version !== 'browser_content_event_v1'
          || sender.id !== api.runtime.id || !sender.tab || sender.tab.active !== true) return;
      const destination = protocol.normalizeUrl(sender.tab.url);
      if (!destination) return;
      const common = {
        schema_version: 'browser_sensor_event_v1', protocol_version: PROTOCOL_VERSION,
        event_identifier: uuid(), browser_family: family,
        destination_origin: destination.origin, destination_domain: destination.domain,
        observed_at: observedAt(),
      };
      if (message.kind === 'upload' && protocol.validateUploadMetadata(message.metadata)) {
        post({ ...common, event_type: 'BROWSER_UPLOAD', ...message.metadata });
      } else if (message.kind === 'paste' && protocol.validatePasteMetadata(message.metadata)) {
        post({ ...common, event_type: 'BROWSER_PASTE', ...message.metadata });
      }
    }

    api.runtime.onMessage.addListener(onContentMessage);
    api.tabs.onActivated.addListener(({ tabId }) => {
      api.tabs.get(tabId).then(reportTab).catch(() => {});
    });
    api.tabs.onUpdated.addListener((_tabId, change, tab) => {
      if (change.url) reportTab(tab);
    });
    api.alarms.onAlarm.addListener((alarm) => {
      if (alarm.name === ALARM) {
        connect();
        heartbeat();
        void reportCurrentTab();
      }
    });
    function start() {
      api.alarms.create(ALARM, { periodInMinutes: 1 });
      connect();
      void reportCurrentTab();
    }
    api.runtime.onStartup.addListener(start);
    api.runtime.onInstalled.addListener(start);
    start();
    return Object.freeze({ heartbeat, reportTab, connect });
  }

  if (typeof module === 'object' && module.exports) module.exports = { createBrowserSensorRuntime };
  else createBrowserSensorRuntime(root.chrome);
})(globalThis);
