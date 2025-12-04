import { Buffer } from 'buffer';
import { CodedError } from 'expo-modules-core';
import { CryptoEncoding, } from './Crypto.types';
const { TextEncoder: NodeTextEncoder } = typeof window === 'undefined' ? require('util') : { TextEncoder: undefined };
const getCrypto = () => window.crypto ?? window.msCrypto;
export default {
    async digestStringAsync(algorithm, data, options) {
        if (!crypto.subtle) {
            throw new CodedError('ERR_CRYPTO_UNAVAILABLE', 'Access to the WebCrypto API is restricted to secure origins (localhost/https).');
        }
        const encoder = new TextEncoder();
        const buffer = encoder.encode(data);
        const hashedData = await crypto.subtle.digest(algorithm, buffer);
        if (options.encoding === CryptoEncoding.HEX) {
            return hexString(hashedData);
        }
        else if (options.encoding === CryptoEncoding.BASE64) {
            return btoa(String.fromCharCode(...new Uint8Array(hashedData)));
        }
        throw new CodedError('ERR_CRYPTO_DIGEST', 'Invalid encoding type provided.');
    },
    getRandomBytes(length) {
        const array = new Uint8Array(length);
        return getCrypto().getRandomValues(array);
    },
    async getRandomBytesAsync(length) {
        const array = new Uint8Array(length);
        return getCrypto().getRandomValues(array);
    },
    getRandomValues(typedArray) {
        return getCrypto().getRandomValues(typedArray);
    },
    randomUUID() {
        return getCrypto().randomUUID();
    },
    digestAsync(algorithm, data) {
        return getCrypto().subtle.digest(algorithm, data);
    },
    async hmacAsync(algorithm, key, data) {
        if (!crypto.subtle) {
            throw new CodedError('ERR_CRYPTO_UNAVAILABLE', 'Access to the WebCrypto API is restricted to secure origins (localhost/https).');
        }
        const hashName = algorithm.split('HMAC-')[1]; // e.g. SHA-256
        const cryptoKey = await crypto.subtle.importKey('raw', toArrayBuffer(key), { name: 'HMAC', hash: { name: hashName } }, false, ['sign']);
        const mac = await crypto.subtle.sign('HMAC', cryptoKey, toArrayBuffer(data));
        return mac;
    },
    hmac(algorithm, output, key, data) {
        // Synchronous-style API that writes into provided output TypedArray to mirror native implementation.
        // Implemented using subtle.sign which is async under the hood; since WebCrypto has no sync HMAC, we throw to encourage using hmacAsync.
        // However, the JS wrapper detects presence of hmac to decide sync vs async path; providing a shim avoids TypeError.
        throw new CodedError('ERR_CRYPTO_UNAVAILABLE', 'Synchronous hmac() is not supported on web. Use hmacAsync via Crypto.hmac instead.');
    },
    async hmacStringAsync(algorithm, key, data, options) {
        const encoder = typeof TextEncoder !== 'undefined' ? new TextEncoder() : new NodeTextEncoder();
        const keyBuf = encoder.encode(key);
        const dataBuf = encoder.encode(data);
        const hashName = algorithm.split('HMAC-')[1];
        if (!hashName) {
            throw new CodedError('ERR_CRYPTO_HMAC', 'Invalid HMAC algorithm format.');
        }
        let mac;
        if (!crypto.subtle) {
            const nodeCrypto = require('crypto');
            const nodeHash = hashName.replace('-', '').toLowerCase();
            const digest = nodeCrypto
                .createHmac(nodeHash, Buffer.from(keyBuf))
                .update(Buffer.from(dataBuf))
                .digest();
            mac = digest;
        }
        else {
            const cryptoKey = await crypto.subtle.importKey('raw', keyBuf, { name: 'HMAC', hash: { name: hashName } }, false, ['sign']);
            mac = await crypto.subtle.sign('HMAC', cryptoKey, dataBuf);
        }
        if (options.encoding === CryptoEncoding.HEX) {
            const bytes = mac instanceof Uint8Array ? mac : new Uint8Array(mac);
            return Array.prototype.map
                .call(bytes, (b) => b.toString(16).padStart(2, '0'))
                .join('');
        }
        else if (options.encoding === CryptoEncoding.BASE64) {
            const buf = mac instanceof Uint8Array ? mac : new Uint8Array(mac);
            return btoa(String.fromCharCode(...buf));
        }
        throw new CodedError('ERR_CRYPTO_HMAC', 'Invalid encoding type provided.');
    },
};
function hexString(buffer) {
    const byteArray = new Uint8Array(buffer);
    const hexCodes = [...byteArray].map((value) => {
        const hexCode = value.toString(16);
        const paddedHexCode = hexCode.padStart(2, '0');
        return paddedHexCode;
    });
    return hexCodes.join('');
}
function toArrayBuffer(data) {
    if (data instanceof ArrayBuffer)
        return data;
    if (ArrayBuffer.isView(data)) {
        return data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength);
    }
    // Fallback: try to handle Uint8Array-like
    const u8 = new Uint8Array(data);
    return u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength);
}
//# sourceMappingURL=ExpoCrypto.web.js.map