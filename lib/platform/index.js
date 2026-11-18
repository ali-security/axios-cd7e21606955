import platform from './node/index.js';

/**
 * Determine if we're running in a browser-like environment (`window` and `document` globals are available)
 *
 * @returns {boolean}
 */
const hasBrowserEnv = typeof window !== 'undefined' && typeof document !== 'undefined';

/**
 * The origin used to resolve relative URLs in a browser-like environment
 */
const origin = hasBrowserEnv && window.location.href || 'http://localhost';

export default Object.assign({
  hasBrowserEnv,
  origin
}, platform);
