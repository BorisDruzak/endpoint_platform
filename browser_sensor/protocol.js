/* Shared, content-free normalization for the MV3 worker and content script. */
(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.EndpointSensorProtocol = api;
})(globalThis, function () {
  'use strict';

  const MAX_MESSAGE_BYTES = 16 * 1024;
  const MAX_FILES = 64;
  const CATEGORIES = new Set(['spreadsheet', 'document', 'image', 'video', 'audio', 'archive', 'other']);
  const CLIPBOARD_TYPES = new Set(['text', 'html', 'image', 'files', 'other']);

  function normalizeUrl(value) {
    if (typeof value !== 'string' || value.length > 4096) return null;
    try {
      const url = new URL(value);
      const scheme = url.protocol.slice(0, -1);
      if (!['http', 'https'].includes(scheme) || !url.hostname || url.hostname.length > 253) return null;
      const origin = url.origin;
      if (origin.length > 512) return null;
      return { scheme, origin, domain: url.hostname.toLowerCase() };
    } catch (_) {
      return null;
    }
  }

  function browserFamily(userAgent) {
    if (typeof userAgent !== 'string') return null;
    if (/YaBrowser\//i.test(userAgent)) return 'yandex';
    if (/(?:Edg|OPR)\//i.test(userAgent)) return null;
    return /Chrome\//i.test(userAgent) ? 'chrome' : null;
  }

  function mimeCategory(type) {
    if (typeof type !== 'string') return 'other';
    const mime = type.toLowerCase().slice(0, 128);
    if (/spreadsheet|excel|csv|sheet/.test(mime)) return 'spreadsheet';
    if (/pdf|word|document|presentation|text\//.test(mime)) return 'document';
    if (mime.startsWith('image/')) return 'image';
    if (mime.startsWith('video/')) return 'video';
    if (mime.startsWith('audio/')) return 'audio';
    if (/zip|gzip|tar|compressed|archive|rar/.test(mime)) return 'archive';
    return 'other';
  }

  function uploadMetadata(files) {
    if (!files || typeof files.length !== 'number' || files.length < 1 || files.length > MAX_FILES) return null;
    let total = 0;
    const categories = new Set();
    for (let index = 0; index < files.length; index += 1) {
      const file = files[index];
      if (!file || !Number.isSafeInteger(file.size) || file.size < 0) return null;
      total += file.size;
      if (!Number.isSafeInteger(total)) return null;
      categories.add(mimeCategory(file.type));
    }
    return { file_count: files.length, total_bytes: total, mime_categories: [...categories].sort() };
  }

  function pasteMetadata(types) {
    if (!types || typeof types.length !== 'number' || types.length > 64) return null;
    const categories = new Set();
    for (const rawType of Array.from(types)) {
      const type = typeof rawType === 'string' ? rawType.toLowerCase() : '';
      if (type === 'text/plain') categories.add('text');
      else if (type === 'text/html') categories.add('html');
      else if (type.startsWith('image/')) categories.add('image');
      else if (type === 'files') categories.add('files');
      else categories.add('other');
    }
    return { clipboard_types: [...categories].sort() };
  }

  function validateUploadMetadata(value) {
    return !!value && Number.isInteger(value.file_count) && value.file_count >= 1 && value.file_count <= MAX_FILES
      && Number.isSafeInteger(value.total_bytes) && value.total_bytes >= 0
      && Array.isArray(value.mime_categories) && value.mime_categories.length <= CATEGORIES.size
      && value.mime_categories.every((item) => CATEGORIES.has(item))
      && Object.keys(value).every((key) => ['file_count', 'total_bytes', 'mime_categories'].includes(key));
  }

  function validatePasteMetadata(value) {
    return !!value && Array.isArray(value.clipboard_types) && value.clipboard_types.length <= CLIPBOARD_TYPES.size
      && value.clipboard_types.every((item) => CLIPBOARD_TYPES.has(item))
      && Object.keys(value).every((key) => key === 'clipboard_types');
  }

  function withinMessageLimit(value) {
    try {
      return new TextEncoder().encode(JSON.stringify(value)).length <= MAX_MESSAGE_BYTES;
    } catch (_) {
      return false;
    }
  }

  return Object.freeze({
    MAX_MESSAGE_BYTES, normalizeUrl, browserFamily, uploadMetadata, pasteMetadata,
    validateUploadMetadata, validatePasteMetadata, withinMessageLimit,
  });
});
