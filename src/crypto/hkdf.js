const u8 = (x) => (x instanceof Uint8Array ? x : new Uint8Array(x));
const concat = (...arrs) => {
  const total = arrs.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrs) {
    out.set(a, off);
    off += a.length;
  }
  return out;
};

export function hkdfExtract(salt, ikm, makeHmacSha256Fn) {
  // If salt is not provided, RFC 5869 uses HashLen zeros.
  const zeroSalt = new Uint8Array(32);
  const s = salt && salt.length ? u8(salt) : zeroSalt;
  const prk = makeHmacSha256Fn(u8(s))(u8(ikm)); // 32 bytes
  return prk;
}

function hkdfExpand(prk, info, length, makeHmacSha256Fn) {
  if (!length || length <= 0) throw new Error("HKDF length must be > 0");
  const hashLen = 32;
  if (length > 255 * hashLen) throw new Error("HKDF length too large");
  const hmac = makeHmacSha256Fn(u8(prk));
  const i = u8(info || new Uint8Array(0));

  let t = new Uint8Array(0);
  const okm = new Uint8Array(length);
  let pos = 0;
  for (let ctr = 1; pos < length; ctr++) {
    const block = hmac(concat(t, i, new Uint8Array([ctr])));
    const take = Math.min(hashLen, length - pos);
    okm.set(block.subarray(0, take), pos);
    pos += take;
    t = block;
  }
  return okm;
}

export function hkdf(
  ikm,
  { salt = new Uint8Array(0), info = new Uint8Array(0), length = 32 } = {},
  makeHmacSha256Fn
) {
  const prk = hkdfExtract(salt, ikm, makeHmacSha256Fn);
  return hkdfExpand(prk, info, length, makeHmacSha256Fn);
}
