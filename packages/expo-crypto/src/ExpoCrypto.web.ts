import { Buffer } from 'buffer';
import { CodedError, TypedArray } from 'expo-modules-core';

import {
  CryptoDigestAlgorithm,
  CryptoEncoding,
  CryptoDigestOptions,
  CryptoHmacAlgorithm,
  CryptoHmacOptions,
} from './Crypto.types';

const { TextEncoder: NodeTextEncoder } =
  typeof window === 'undefined' ? require('util') : { TextEncoder: undefined };

const getCrypto = (): Crypto => window.crypto ?? (window as any).msCrypto;

export default {
  async digestStringAsync(
    algorithm: CryptoDigestAlgorithm,
    data: string,
    options: CryptoDigestOptions
  ): Promise<string> {
    if (!crypto.subtle) {
      throw new CodedError(
        'ERR_CRYPTO_UNAVAILABLE',
        'Access to the WebCrypto API is restricted to secure origins (localhost/https).'
      );
    }
    const encoder = new TextEncoder();
    const buffer = encoder.encode(data);
    const hashedData = await crypto.subtle.digest(algorithm, buffer);
    if (options.encoding === CryptoEncoding.HEX) {
      return hexString(hashedData);
    } else if (options.encoding === CryptoEncoding.BASE64) {
      return btoa(String.fromCharCode(...new Uint8Array(hashedData)));
    }
    throw new CodedError('ERR_CRYPTO_DIGEST', 'Invalid encoding type provided.');
  },
  getRandomBytes(length: number): Uint8Array {
    const array = new Uint8Array(length);
    return getCrypto().getRandomValues(array);
  },
  async getRandomBytesAsync(length: number): Promise<Uint8Array> {
    const array = new Uint8Array(length);
    return getCrypto().getRandomValues(array);
  },
  getRandomValues(typedArray: TypedArray) {
    return getCrypto().getRandomValues(typedArray);
  },
  randomUUID() {
    return getCrypto().randomUUID();
  },
  digestAsync(algorithm: AlgorithmIdentifier, data: ArrayBuffer): Promise<ArrayBuffer> {
    return getCrypto().subtle.digest(algorithm, data);
  },
  async hmacAsync(
    algorithm: CryptoHmacAlgorithm,
    key: BufferSource,
    data: BufferSource
  ): Promise<ArrayBuffer> {
    if (!crypto.subtle) {
      throw new CodedError(
        'ERR_CRYPTO_UNAVAILABLE',
        'Access to the WebCrypto API is restricted to secure origins (localhost/https).'
      );
    }
    const hashName = algorithm.split('HMAC-')[1]; // e.g. SHA-256
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      toArrayBuffer(key),
      { name: 'HMAC', hash: { name: hashName } },
      false,
      ['sign']
    );
    const mac = await crypto.subtle.sign('HMAC', cryptoKey, toArrayBuffer(data));
    return mac;
  },
  hmac(
    algorithm: CryptoHmacAlgorithm,
    output: TypedArray,
    key: BufferSource,
    data: BufferSource
  ): void {
    // Synchronous-style API that writes into provided output TypedArray to mirror native implementation.
    // Implemented using subtle.sign which is async under the hood; since WebCrypto has no sync HMAC, we throw to encourage using hmacAsync.
    // However, the JS wrapper detects presence of hmac to decide sync vs async path; providing a shim avoids TypeError.
    throw new CodedError(
      'ERR_CRYPTO_UNAVAILABLE',
      'Synchronous hmac() is not supported on web. Use hmacAsync via Crypto.hmac instead.'
    );
  },
  async hmacStringAsync(
    algorithm: CryptoHmacAlgorithm,
    key: string,
    data: string,
    options: CryptoHmacOptions
  ): Promise<string> {
    const encoder = typeof TextEncoder !== 'undefined' ? new TextEncoder() : new NodeTextEncoder();
    const keyBuf = encoder.encode(key);
    const dataBuf = encoder.encode(data);
    const hashName = algorithm.split('HMAC-')[1];
    if (!hashName) {
      throw new CodedError('ERR_CRYPTO_HMAC', 'Invalid HMAC algorithm format.');
    }
    let mac: ArrayBuffer | Uint8Array;
    if (!crypto.subtle) {
      const nodeCrypto = require('crypto');
      const nodeHash = hashName.replace('-', '').toLowerCase();
      const digest = nodeCrypto
        .createHmac(nodeHash, Buffer.from(keyBuf))
        .update(Buffer.from(dataBuf))
        .digest();
      mac = digest;
    } else {
      const cryptoKey = await crypto.subtle.importKey(
        'raw',
        keyBuf,
        { name: 'HMAC', hash: { name: hashName } },
        false,
        ['sign']
      );
      mac = await crypto.subtle.sign('HMAC', cryptoKey, dataBuf);
    }
    if (options.encoding === CryptoEncoding.HEX) {
      const bytes = mac instanceof Uint8Array ? mac : new Uint8Array(mac as ArrayBuffer);
      return Array.prototype.map
        .call(bytes, (b: number) => b.toString(16).padStart(2, '0'))
        .join('');
    } else if (options.encoding === CryptoEncoding.BASE64) {
      const buf = mac instanceof Uint8Array ? mac : new Uint8Array(mac as ArrayBuffer);
      return btoa(String.fromCharCode(...buf));
    }
    throw new CodedError('ERR_CRYPTO_HMAC', 'Invalid encoding type provided.');
  },
};

function hexString(buffer: ArrayBuffer): string {
  const byteArray = new Uint8Array(buffer);

  const hexCodes = [...byteArray].map((value) => {
    const hexCode = value.toString(16);
    const paddedHexCode = hexCode.padStart(2, '0');
    return paddedHexCode;
  });

  return hexCodes.join('');
}

function toArrayBuffer(data: BufferSource): ArrayBuffer {
  if (data instanceof ArrayBuffer) return data;
  if (ArrayBuffer.isView(data)) {
    return data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength);
  }
  // Fallback: try to handle Uint8Array-like
  const u8 = new Uint8Array(data as any);
  return u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength);
}
