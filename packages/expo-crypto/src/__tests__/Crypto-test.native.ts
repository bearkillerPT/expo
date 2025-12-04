import * as Crypto from '../Crypto';
import ExpoCrypto from '../ExpoCrypto';

it(`invokes native method correctly`, async () => {
  const value = await Crypto.digestStringAsync(Crypto.CryptoDigestAlgorithm.SHA1, '<DEBUG>', {
    encoding: Crypto.CryptoEncoding.HEX,
  });
  expect(typeof value).toBe('string');
  expect(ExpoCrypto.digestStringAsync).toHaveBeenLastCalledWith(
    Crypto.CryptoDigestAlgorithm.SHA1,
    '<DEBUG>',
    {
      encoding: Crypto.CryptoEncoding.HEX,
    }
  );
});

it(`invokes native method correctly`, async () => {
  const value = await Crypto.getRandomBytesAsync(0);
  expect(value instanceof Uint8Array).toBe(true);
  expect(ExpoCrypto.getRandomValues).toHaveBeenLastCalledWith(value);
});

it(`returns an array with the desired number of bytes`, async () => {
  const value = await Crypto.getRandomBytesAsync(3);
  expect(value.length).toBe(3);
});

it(`accepts valid byte counts`, async () => {
  await expect(Crypto.getRandomBytesAsync(0));
  await expect(Crypto.getRandomBytesAsync(1024));
  await expect(Crypto.getRandomBytesAsync(512.5));
});

// HMAC behavior-only tests (native)
it('invokes native hmac and returns ArrayBuffer', async () => {
  const key = new Uint8Array([1, 2, 3]);
  const data = new Uint8Array([4, 5, 6]);
  const buf = await Crypto.hmac(Crypto.CryptoHmacAlgorithm.SHA256, key, data);
  expect(buf instanceof ArrayBuffer).toBe(true);
});

it('invokes native hmacStringAsync and returns string', async () => {
  const value = await Crypto.hmacStringAsync(Crypto.CryptoHmacAlgorithm.SHA1, 'k', 'd', {
    encoding: Crypto.CryptoEncoding.HEX,
  });
  expect(typeof value).toBe('string');
});
