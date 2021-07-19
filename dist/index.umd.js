(function (global, factory) {
  typeof exports === 'object' && typeof module !== 'undefined' ? factory(exports, require('crypto-js/aes'), require('crypto-js/enc-base64'), require('crypto-js/enc-hex'), require('lodash-es')) :
  typeof define === 'function' && define.amd ? define(['exports', 'crypto-js/aes', 'crypto-js/enc-base64', 'crypto-js/enc-hex', 'lodash-es'], factory) :
  (global = typeof globalThis !== 'undefined' ? globalThis : global || self, factory(global.useCrypto = {}, global.AES, global.base64, global.hex, global.lodashEs));
}(this, (function (exports, AES, base64, hex, lodashEs) { 'use strict';

  function _interopDefaultLegacy (e) { return e && typeof e === 'object' && 'default' in e ? e : { 'default': e }; }

  var AES__default = /*#__PURE__*/_interopDefaultLegacy(AES);
  var base64__default = /*#__PURE__*/_interopDefaultLegacy(base64);
  var hex__default = /*#__PURE__*/_interopDefaultLegacy(hex);

  const randomString = function randomString(len) {
    const dictionary =
      '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    let result = '';

    for (let i = 0; i < len; i += 1) {
      const random = Math.floor(Math.random() * dictionary.length);
      const char = dictionary.charAt(random);

      result += char;
    }

    return result
  };

  const aesEncrypt = function aesEncrypt(secret, data) {
    const str = JSON.stringify(data || {});
    const key = hex__default['default'].parse(secret);
    const iv = hex__default['default'].parse(secret);
    const cipher = AES__default['default'].encrypt(str, key, {
      iv,
    });
    const result = base64__default['default'].stringify(cipher.ciphertext);

    return result
  };

  function generateSecret() {
    const random = randomString(43);
    const str = `${random}=`;

    return hex__default['default'].stringify(base64__default['default'].parse(str))
  }

  /**
   *
   * @param {Object} options
   * @param {string} options.secret
   *
   * @returns interceptor
   */
  function useCrypto(options = {}) {
    const { secret } = options;

    if (!secret) {
      throw Error('secret is required.')
    }

    return async function interceptor(config) {
      const { method, params, data } = config;

      const hasParams = params && Object.keys(params).length > 0;
      const hasBody = data && Object.keys(data).length > 0;
      const timestamp = Date.now();
      const nonce = randomString(32);

      if (method === 'get' || method === 'delete' || hasParams) {
        const { key } = params;
        const payload = lodashEs.assign(lodashEs.omit(params, ['key']), {
          timestamp,
          nonce,
        });
        const cipherText = aesEncrypt(secret, payload);

        config.params = {
          key,
          cipherText,
        };
      }

      if (
        method === 'post' ||
        method === 'put' ||
        method === 'patch' ||
        hasBody
      ) {
        const { key } = data;
        const payload = lodashEs.assign({}, lodashEs.omit(data, ['key']), {
          timestamp,
          nonce,
        });
        const cipherText = aesEncrypt(secret, payload);

        config.data = {
          key,
          cipherText,
        };
      }

      return config
    }
  }

  exports.generateSecret = generateSecret;
  exports.useCrypto = useCrypto;

  Object.defineProperty(exports, '__esModule', { value: true });

})));
