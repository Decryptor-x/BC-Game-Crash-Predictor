/*
 * [js-sha256]{@link https://github.com/decryptor-x/BC-Game-Crash-Predictor}
 *
 * @version 1.1.0
 * @author Decryptor
 * @copyright Decryptor 2016-2025
 * @license MIT
 */
(function globalWrapper() {
  'use strict';

  // error messages
  var ERR_BAD_INPUT = 'input is invalid type';
  var ERR_ALREADY_FINALIZED = 'finalize already called';

  // environment detection
  var __hasWindow = typeof window === 'object';
  var __root = __hasWindow ? window : {};
  if (__root.JS_SHA1_NO_WINDOW) __hasWindow = false;

  var __isWorker = !__hasWindow && typeof self === 'object';
  var __isNode = !__root.JS_SHA1_NO_NODE_JS && typeof process === 'object' && process.versions && process.versions.node;
  if (__isNode) __root = global;
  else if (__isWorker) __root = self;

  var __isCommonJS = !_root.JS_SHA1_NO_COMMON_JS && typeof module === 'object' && module.exports;
  var __isAmd = typeof define === 'function' && define.amd;
  var __hasArrayBuffer = !_root.JS_SHA1_NO_ARRAY_BUFFER && typeof ArrayBuffer !== 'undefined';

  // small constants and tables
  var HEX_TABLE = '0123456789abcdef'.split('');
  var PAD_TABLE = [-2147483648, 8388608, 32768, 128];
  var BYTE_SHIFT = [24, 16, 8, 0];
  var OUTPUT_TYPES = ['hex', 'array', 'digest', 'arrayBuffer'];

  // shared scratch for micro-optimizations
  var SHARED_SCRATCH = [];

  // array detection helpers (fall back if environment restricts)
  var nativeIsArray = Array.isArray;
  if (__root.JS_SHA1_NO_NODE_JS || !nativeIsArray) {
    nativeIsArray = function (v) { return Object.prototype.toString.call(v) === '[object Array]'; };
  }

  var isArrayBufferView = ArrayBuffer.isView;
  if (__hasArrayBuffer && (__root.JS_SHA1_NO_ARRAY_BUFFER_IS_VIEW || !isArrayBufferView)) {
    isArrayBufferView = function (v) {
      return typeof v === 'object' && v.buffer && v.buffer.constructor === ArrayBuffer;
    };
  }

  // normalize input: returns [data, isStringFlag]
  function normalizeInput(input) {
    var t = typeof input;
    if (t === 'string') return [input, true];
    if (t !== 'object' || input === null) throw new Error(ERR_BAD_INPUT);
    if (__hasArrayBuffer && input.constructor === ArrayBuffer) return [new Uint8Array(input), false];
    if (!nativeIsArray(input) && !isArrayBufferView(input)) throw new Error(ERR_BAD_INPUT);
    return [input, false];
  }

  // create output functions for different result formats
  function outputFactory(format) {
    return function (msg) {
      return new CoreSha1(true).update(msg)[format]();
    };
  }

  // top-level factory (sha1())
  function factoryMaker() {
    var main = outputFactory('hex');
    if (__isNode) main = nodeOptimized(main);

    main.create = function () { return new CoreSha1(); };
    main.update = function (m) { return main.create().update(m); };

    for (var i = 0; i < OUTPUT_TYPES.length; ++i) {
      var f = OUTPUT_TYPES[i];
      main[f] = outputFactory(f);
    }
    return main;
  }

  // node-specific fast path using built-in crypto
  function nodeOptimized(base) {
    var crypto = require('crypto');
    var BufferCtor = require('buffer').Buffer;
    var fromBuffer = BufferCtor.from && !_root.JS_SHA1_NO_BUFFER_FROM ? BufferCtor.from : function (x) { return new BufferCtor(x); };

    return function (msg) {
      if (typeof msg === 'string') return crypto.createHash('sha1').update(msg, 'utf8').digest('hex');
      if (msg === null || msg === undefined) throw new Error(ERR_BAD_INPUT);
      if (msg.constructor === ArrayBuffer) msg = new Uint8Array(msg);
      if (nativeIsArray(msg) || isArrayBufferView(msg) || msg.constructor === BufferCtor) {
        return crypto.createHash('sha1').update(fromBuffer(msg)).digest('hex');
      }
      return base(msg);
    };
  }

  // hmac output generator
  function makeHmacOutput(kind) {
    return function (k, m) {
      return new HmacSha1(k, true).update(m)[kind]();
    };
  }

  function makeHmacFactory() {
    var h = makeHmacOutput('hex');
    h.create = function (key) { return new HmacSha1(key); };
    h.update = function (key, msg) { return h.create(key).update(msg); };

    for (var j = 0; j < OUTPUT_TYPES.length; ++j) {
      (function (t) { h[t] = makeHmacOutput(t); })(OUTPUT_TYPES[j]);
    }
    return h;
  }

  // --- CORE SHA-1 IMPLEMENTATION ---
  function CoreSha1(useShared) {
    if (useShared) {
      // populate shared scratch with zeroes (16 + 1 used slots)
      SHARED_SCRATCH[0] = SHARED_SCRATCH[16] = SHARED_SCRATCH[1] = SHARED_SCRATCH[2] =
      SHARED_SCRATCH[3] = SHARED_SCRATCH[4] = SHARED_SCRATCH[5] = SHARED_SCRATCH[6] =
      SHARED_SCRATCH[7] = SHARED_SCRATCH[8] = SHARED_SCRATCH[9] = SHARED_SCRATCH[10] =
      SHARED_SCRATCH[11] = SHARED_SCRATCH[12] = SHARED_SCRATCH[13] = SHARED_SCRATCH[14] =
      SHARED_SCRATCH[15] = 0;
      this._w = SHARED_SCRATCH;
    } else {
      this._w = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
    }

    // initial state constants
    this._a = 0x67452301;
    this._b = 0xEFCDAB89;
    this._c = 0x98BADCFE;
    this._d = 0x10325476;
    this._e = 0xC3D2E1F0;

    this.block = this.start = this.bytes = this.hiBytes = 0;
    this.finalized = this.hashed = false;
    this.first = true;
  }

  CoreSha1.prototype.update = function (msg) {
    if (this.finalized) throw new Error(ERR_ALREADY_FINALIZED);

    var pair = normalizeInput(msg);
    msg = pair[0];
    var isString = pair[1];

    var code = 0, idx = 0, i, len = msg.length || 0, w = this._w;

    while (idx < len) {
      if (this.hashed) {
        this.hashed = false;
        w[0] = this.block;
        this.block = w[16] = w[1] = w[2] = w[3] =
        w[4] = w[5] = w[6] = w[7] =
        w[8] = w[9] = w[10] = w[11] =
        w[12] = w[13] = w[14] = w[15] = 0;
      }

      if (isString) {
        for (i = this.start; idx < len && i < 64; ++idx) {
          code = msg.charCodeAt(idx);
          if (code < 0x80) {
            w[i >>> 2] |= code << BYTE_SHIFT[i++ & 3];
          } else if (code < 0x800) {
            w[i >>> 2] |= (0xc0 | (code >>> 6)) << BYTE_SHIFT[i++ & 3];
            w[i >>> 2] |= (0x80 | (code & 0x3f)) << BYTE_SHIFT[i++ & 3];
          } else if (code < 0xD800 || code >= 0xE000) {
            w[i >>> 2] |= (0xe0 | (code >>> 12)) << BYTE_SHIFT[i++ & 3];
            w[i >>> 2] |= (0x80 | ((code >>> 6) & 0x3f)) << BYTE_SHIFT[i++ & 3];
            w[i >>> 2] |= (0x80 | (code & 0x3f)) << BYTE_SHIFT[i++ & 3];
          } else {
            // surrogate pair handling
            code = 0x10000 + (((code & 0x3ff) << 10) | (msg.charCodeAt(++idx) & 0x3ff));
            w[i >>> 2] |= (0xf0 | (code >>> 18)) << BYTE_SHIFT[i++ & 3];
            w[i >>> 2] |= (0x80 | ((code >>> 12) & 0x3f)) << BYTE_SHIFT[i++ & 3];
            w[i >>> 2] |= (0x80 | ((code >>> 6) & 0x3f)) << BYTE_SHIFT[i++ & 3];
            w[i >>> 2] |= (0x80 | (code & 0x3f)) << BYTE_SHIFT[i++ & 3];
          }
        }
      } else {
        for (i = this.start; idx < len && i < 64; ++idx) {
          w[i >>> 2] |= msg[idx] << BYTE_SHIFT[i++ & 3];
        }
      }

      this.lastByteIndex = i;
      this.bytes += i - this.start;

      if (i >= 64) {
        this.block = w[16];
        this.start = i - 64;
        this._compress();
        this.hashed = true;
      } else {
        this.start = i;
      }
    }

    if (this.bytes > 0xFFFFFFFF) {
      this.hiBytes += (this.bytes / 4294967296) | 0;
      this.bytes = this.bytes % 4294967296;
    }
    return this;
  };

  CoreSha1.prototype.finalize = function () {
    if (this.finalized) return;
    this.finalized = true;

    var w = this._w, j = this.lastByteIndex;
    w[16] = this.block;
    w[j >>> 2] |= PAD_TABLE[j & 3];
    this.block = w[16];

    if (j >= 56) {
      if (!this.hashed) this._compress();
      w[0] = this.block;
      w[16] = w[1] = w[2] = w[3] =
      w[4] = w[5] = w[6] = w[7] =
      w[8] = w[9] = w[10] = w[11] =
      w[12] = w[13] = w[14] = w[15] = 0;
    }

    w[14] = (this.hiBytes << 3) | (this.bytes >>> 29);
    w[15] = this.bytes << 3;
    this._compress();
  };

  // compression (same algorithm, renamed locals)
  CoreSha1.prototype._compress = function () {
    var a = this._a, b = this._b, c = this._c, d = this._d, e = this._e;
    var t, W = this._w;

    for (var i = 16; i < 80; ++i) {
      t = W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16];
      W[i] = (t << 1) | (t >>> 31);
    }

    var k = 0;
    for (; k < 20; k += 5) {
      var f = (b & c) | ((~b) & d);
      t = ((a << 5) | (a >>> 27)) + f + e + 1518500249 + (W[k] << 0);
      e = ((t << 0) | 0);
      b = (b << 30) | (b >>> 2);

      f = (a & b) | ((~a) & c);
      t = ((e << 5) | (e >>> 27)) + f + d + 1518500249 + (W[k + 1] << 0);
      d = ((t << 0) | 0);
      a = (a << 30) | (a >>> 2);

      f = (e & a) | ((~e) & b);
      t = ((d << 5) | (d >>> 27)) + f + c + 1518500249 + (W[k + 2] << 0);
      c = ((t << 0) | 0);
      e = (e << 30) | (e >>> 2);

      f = (d & e) | ((~d) & a);
      t = ((c << 5) | (c >>> 27)) + f + b + 1518500249 + (W[k + 3] << 0);
      b = ((t << 0) | 0);
      d = (d << 30) | (d >>> 2);

      f = (c & b) | ((~c) & e);
      t = ((b << 5) | (b >>> 27)) + f + a + 1518500249 + (W[k + 4] << 0);
      a = ((t << 0) | 0);
      c = (c << 30) | (c >>> 2);
    }

    for (; k < 40; k += 5) {
      var ff = b ^ c ^ d;
      t = ((a << 5) | (a >>> 27)) + ff + e + 1859775393 + (W[k] << 0);
      e = ((t << 0) | 0);
      b = (b << 30) | (b >>> 2);

      ff = a ^ b ^ c;
      t = ((e << 5) | (e >>> 27)) + ff + d + 1859775393 + (W[k + 1] << 0);
      d = ((t << 0) | 0);
      a = (a << 30) | (a >>> 2);

      ff = e ^ a ^ b;
      t = ((d << 5) | (d >>> 27)) + ff + c + 1859775393 + (W[k + 2] << 0);
      c = ((t << 0) | 0);
      e = (e << 30) | (e >>> 2);

      ff = d ^ e ^ a;
      t = ((c << 5) | (c >>> 27)) + ff + b + 1859775393 + (W[k + 3] << 0);
      b = ((t << 0) | 0);
      d = (d << 30) | (d >>> 2);

      ff = c ^ b ^ e;
      t = ((b << 5) | (b >>> 27)) + ff + a + 1859775393 + (W[k + 4] << 0);
      a = ((t << 0) | 0);
      c = (c << 30) | (c >>> 2);
    }

    for (; k < 60; k += 5) {
      var fff = (b & c) | (b & d) | (c & d);
      t = ((a << 5) | (a >>> 27)) + fff + e - 1894007588 + (W[k] << 0);
      e = ((t << 0) | 0);
      b = (b << 30) | (b >>> 2);

      fff = (a & b) | (a & c) | (b & c);
      t = ((e << 5) | (e >>> 27)) + fff + d - 1894007588 + (W[k + 1] << 0);
      d = ((t << 0) | 0);
      a = (a << 30) | (a >>> 2);

      fff = (e & a) | (e & b) | (a & b);
      t = ((d << 5) | (d >>> 27)) + fff + c - 1894007588 + (W[k + 2] << 0);
      c = ((t << 0) | 0);
      e = (e << 30) | (e >>> 2);

      fff = (d & e) | (d & a) | (e & a);
      t = ((c << 5) | (c >>> 27)) + fff + b - 1894007588 + (W[k + 3] << 0);
      b = ((t << 0) | 0);
      d = (d << 30) | (d >>> 2);

      fff = (c & b) | (c & e) | (b & e);
      t = ((b << 5) | (b >>> 27)) + fff + a - 1894007588 + (W[k + 4] << 0);
      a = ((t << 0) | 0);
      c = (c << 30) | (c >>> 2);
    }

    for (; k < 80; k += 5) {
      var ffff = b ^ c ^ d;
      t = ((a << 5) | (a >>> 27)) + ffff + e - 899497514 + (W[k] << 0);
      e = ((t << 0) | 0);
      b = (b << 30) | (b >>> 2);

      ffff = a ^ b ^ c;
      t = ((e << 5) | (e >>> 27)) + ffff + d - 899497514 + (W[k + 1] << 0);
      d = ((t << 0) | 0);
      a = (a << 30) | (a >>> 2);

      ffff = e ^ a ^ b;
      t = ((d << 5) | (d >>> 27)) + ffff + c - 899497514 + (W[k + 2] << 0);
      c = ((t << 0) | 0);
      e = (e << 30) | (e >>> 2);

      ffff = d ^ e ^ a;
      t = ((c << 5) | (c >>> 27)) + ffff + b - 899497514 + (W[k + 3] << 0);
      b = ((t << 0) | 0);
      d = (d << 30) | (d >>> 2);

      ffff = c ^ b ^ e;
      t = ((b << 5) | (b >>> 27)) + ffff + a - 899497514 + (W[k + 4] << 0);
      a = ((t << 0) | 0);
      c = (c << 30) | (c >>> 2);
    }

    this._a = (this._a + a) << 0;
    this._b = (this._b + b) << 0;
    this._c = (this._c + c) << 0;
    this._d = (this._d + d) << 0;
    this._e = (this._e + e) << 0;
  };

  // produce hex string
  CoreSha1.prototype.hex = function () {
    this.finalize();
    var a = this._a, b = this._b, c = this._c, d = this._d, e = this._e;
    return HEX_TABLE[(a >>> 28) & 0x0F] + HEX_TABLE[(a >>> 24) & 0x0F] +
           HEX_TABLE[(a >>> 20) & 0x0F] + HEX_TABLE[(a >>> 16) & 0x0F] +
           HEX_TABLE[(a >>> 12) & 0x0F] + HEX_TABLE[(a >>> 8) & 0x0F] +
           HEX_TABLE[(a >>> 4) & 0x0F] + HEX_TABLE[a & 0x0F] +
           HEX_TABLE[(b >>> 28) & 0x0F] + HEX_TABLE[(b >>> 24) & 0x0F] +
           HEX_TABLE[(b >>> 20) & 0x0F] + HEX_TABLE[(b >>> 16) & 0x0F] +
           HEX_TABLE[(b >>> 12) & 0x0F] + HEX_TABLE[(b >>> 8) & 0x0F] +
           HEX_TABLE[(b >>> 4) & 0x0F] + HEX_TABLE[b & 0x0F] +
           HEX_TABLE[(c >>> 28) & 0x0F] + HEX_TABLE[(c >>> 24) & 0x0F] +
           HEX_TABLE[(c >>> 20) & 0x0F] + HEX_TABLE[(c >>> 16) & 0x0F] +
           HEX_TABLE[(c >>> 12) & 0x0F] + HEX_TABLE[(c >>> 8) & 0x0F] +
           HEX_TABLE[(c >>> 4) & 0x0F] + HEX_TABLE[c & 0x0F] +
           HEX_TABLE[(d >>> 28) & 0x0F] + HEX_TABLE[(d >>> 24) & 0x0F] +
           HEX_TABLE[(d >>> 20) & 0x0F] + HEX_TABLE[(d >>> 16) & 0x0F] +
           HEX_TABLE[(d >>> 12) & 0x0F] + HEX_TABLE[(d >>> 8) & 0x0F] +
           HEX_TABLE[(d >>> 4) & 0x0F] + HEX_TABLE[d & 0x0F] +
           HEX_TABLE[(e >>> 28) & 0x0F] + HEX_TABLE[(e >>> 24) & 0x0F] +
           HEX_TABLE[(e >>> 20) & 0x0F] + HEX_TABLE[(e >>> 16) & 0x0F] +
           HEX_TABLE[(e >>> 12) & 0x0F] + HEX_TABLE[(e >>> 8) & 0x0F] +
           HEX_TABLE[(e >>> 4) & 0x0F] + HEX_TABLE[e & 0x0F];
  };

  CoreSha1.prototype.toString = CoreSha1.prototype.hex;

  // produce raw byte array
  CoreSha1.prototype.digest = function () {
    this.finalize();
    var a = this._a, b = this._b, c = this._c, d = this._d, e = this._e;
    return [
      (a >>> 24) & 0xFF, (a >>> 16) & 0xFF, (a >>> 8) & 0xFF, a & 0xFF,
      (b >>> 24) & 0xFF, (b >>> 16) & 0xFF, (b >>> 8) & 0xFF, b & 0xFF,
      (c >>> 24) & 0xFF, (c >>> 16) & 0xFF, (c >>> 8) & 0xFF, c & 0xFF,
      (d >>> 24) & 0xFF, (d >>> 16) & 0xFF, (d >>> 8) & 0xFF, d & 0xFF,
      (e >>> 24) & 0xFF, (e >>> 16) & 0xFF, (e >>> 8) & 0xFF, e & 0xFF
    ];
  };

  CoreSha1.prototype.array = CoreSha1.prototype.digest;

  CoreSha1.prototype.arrayBuffer = function () {
    this.finalize();
    var buffer = new ArrayBuffer(20);
    var view = new DataView(buffer);
    view.setUint32(0, this._a);
    view.setUint32(4, this._b);
    view.setUint32(8, this._c);
    view.setUint32(12, this._d);
    view.setUint32(16, this._e);
    return buffer;
  };

  // --- HMAC wrapper using CoreSha1 ---
  function HmacSha1(key, useShared) {
    var pair = normalizeInput(key);
    key = pair[0];

    if (pair[1]) {
      var bytes = [], p = 0, ch;
      for (var i = 0, L = key.length; i < L; ++i) {
        ch = key.charCodeAt(i);
        if (ch < 0x80) {
          bytes[p++] = ch;
        } else if (ch < 0x800) {
          bytes[p++] = 0xc0 | (ch >>> 6);
          bytes[p++] = 0x80 | (ch & 0x3f);
        } else if (ch < 0xD800 || ch >= 0xE000) {
          bytes[p++] = 0xe0 | (ch >>> 12);
          bytes[p++] = 0x80 | ((ch >>> 6) & 0x3f);
          bytes[p++] = 0x80 | (ch & 0x3f);
        } else {
          ch = 0x10000 + (((ch & 0x3ff) << 10) | (key.charCodeAt(++i) & 0x3ff));
          bytes[p++] = 0xf0 | (ch >>> 18);
          bytes[p++] = 0x80 | ((ch >>> 12) & 0x3f);
          bytes[p++] = 0x80 | ((ch >>> 6) & 0x3f);
          bytes[p++] = 0x80 | (ch & 0x3f);
        }
      }
      key = bytes;
    }

    if (key.length > 64) key = (new CoreSha1(true)).update(key).array();

    var oPad = [], iPad = [];
    for (i = 0; i < 64; ++i) {
      var b = key[i] || 0;
      oPad[i] = 0x5c ^ b;
      iPad[i] = 0x36 ^ b;
    }

    CoreSha1.call(this, useShared);
    this.update(iPad);
    this._oKey = oPad;
    this._isInner = true;
    this._sharedFlag = useShared;
  }
  HmacSha1.prototype = new CoreSha1();

  HmacSha1.prototype.finalize = function () {
    CoreSha1.prototype.finalize.call(this);
    if (this._isInner) {
      this._isInner = false;
      var inner = this.array();
      CoreSha1.call(this, this._sharedFlag);
      this.update(this._oKey);
      this.update(inner);
      CoreSha1.prototype.finalize.call(this);
    }
  };

  // --- Public API wiring ---
  var api = factoryMaker();
  api.sha1 = api;
  api.sha1.hmac = makeHmacFactory();

  if (__isCommonJS) {
    module.exports = api;
  } else {
    __root.sha1 = api;
    if (__isAmd) {
      define(function () { return api; });
    }
  }

})();