/* Observe browser-visible actions without reading file names or clipboard values. */
(function (root) {
  'use strict';

  function createContentSensor(documentRef, runtime, protocol) {
    function send(kind, metadata) {
      if (!metadata) return;
      const message = { schema_version: 'browser_content_event_v1', kind, metadata };
      if (!protocol.withinMessageLimit(message)) return;
      try {
        const result = runtime.sendMessage(message);
        if (result && typeof result.catch === 'function') result.catch(() => {});
      } catch (_) {
        // The worker can be unavailable while the browser is shutting down.
      }
    }

    function onFileChange(event) {
      if (event.isTrusted === false) return;
      const input = event.target;
      if (!input || input.tagName !== 'INPUT' || input.type !== 'file') return;
      send('upload', protocol.uploadMetadata(input.files));
    }

    function onPaste(event) {
      if (event.isTrusted === false) return;
      const types = event.clipboardData && event.clipboardData.types;
      send('paste', protocol.pasteMetadata(types));
    }

    documentRef.addEventListener('change', onFileChange, true);
    documentRef.addEventListener('paste', onPaste, true);
    return { stop() {
      documentRef.removeEventListener('change', onFileChange, true);
      documentRef.removeEventListener('paste', onPaste, true);
    } };
  }

  if (typeof module === 'object' && module.exports) module.exports = { createContentSensor };
  else createContentSensor(root.document, root.chrome.runtime, root.EndpointSensorProtocol);
})(globalThis);
