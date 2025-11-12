// ---------------------- Byte utils ---------------------------
const toU8 = (v) => (v instanceof Uint8Array ? v : new Uint8Array(v));
const concat = (a, b) => {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
};
const i32be = (x) =>
  new Uint8Array([
    (x >>> 24) & 0xff,
    (x >>> 16) & 0xff,
    (x >>> 8) & 0xff,
    x & 0xff,
  ]);

// ---------------------- SHA-256 ---------------------
// References: FIPS 180-4
const K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
  0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
  0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
  0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
  0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
  0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);
const ROTR = (x, n) => (x >>> n) | (x << (32 - n));
const Ch = (x, y, z) => (x & y) ^ (~x & z);
const Maj = (x, y, z) => (x & y) ^ (x & z) ^ (y & z);
const Sigma0 = (x) => ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22);
const Sigma1 = (x) => ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25);
const sigma0 = (x) => ROTR(x, 7) ^ ROTR(x, 18) ^ (x >>> 3);
const sigma1 = (x) => ROTR(x, 17) ^ ROTR(x, 19) ^ (x >>> 10);

export function sha256(msgU8) {
  const m = toU8(msgU8);
  // Init state
  let h0 = 0x6a09e667,
    h1 = 0xbb67ae85,
    h2 = 0x3c6ef372,
    h3 = 0xa54ff53a;
  let h4 = 0x510e527f,
    h5 = 0x9b05688c,
    h6 = 0x1f83d9ab,
    h7 = 0x5be0cd19;

  // Pre-processing (padding)
  const bitLenHi = Math.floor((m.length / 0x20000000) >>> 0); // high 32 bits (rarely non-zero)
  const bitLenLo = ((m.length >>> 0) * 8) >>> 0; // low 32 bits
  const k = -(m.length + 9) & 63;
  const padded = new Uint8Array(m.length + 1 + k + 8);
  padded.set(m, 0);
  padded[m.length] = 0x80;
  // big-endian 64-bit length
  padded[padded.length - 8] = (bitLenHi >>> 24) & 0xff;
  padded[padded.length - 7] = (bitLenHi >>> 16) & 0xff;
  padded[padded.length - 6] = (bitLenHi >>> 8) & 0xff;
  padded[padded.length - 5] = bitLenHi & 0xff;
  padded[padded.length - 4] = (bitLenLo >>> 24) & 0xff;
  padded[padded.length - 3] = (bitLenLo >>> 16) & 0xff;
  padded[padded.length - 2] = (bitLenLo >>> 8) & 0xff;
  padded[padded.length - 1] = bitLenLo & 0xff;

  const W = new Uint32Array(64);

  for (let off = 0; off < padded.length; off += 64) {
    // Prepare message schedule
    for (let i = 0; i < 16; i++) {
      const j = off + (i << 2);
      W[i] =
        (padded[j] << 24) |
        (padded[j + 1] << 16) |
        (padded[j + 2] << 8) |
        padded[j + 3];
    }
    for (let i = 16; i < 64; i++) {
      W[i] =
        (sigma1(W[i - 2]) + W[i - 7] + sigma0(W[i - 15]) + W[i - 16]) >>> 0;
    }

    // Working vars
    let a = h0,
      b = h1,
      c = h2,
      d = h3,
      e = h4,
      f = h5,
      g = h6,
      h = h7;

    for (let i = 0; i < 64; i++) {
      const t1 = (h + Sigma1(e) + Ch(e, f, g) + K[i] + W[i]) >>> 0;
      const t2 = (Sigma0(a) + Maj(a, b, c)) >>> 0;
      h = g;
      g = f;
      f = e;
      e = (d + t1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (t1 + t2) >>> 0;
    }

    h0 = (h0 + a) >>> 0;
    h1 = (h1 + b) >>> 0;
    h2 = (h2 + c) >>> 0;
    h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0;
    h5 = (h5 + f) >>> 0;
    h6 = (h6 + g) >>> 0;
    h7 = (h7 + h) >>> 0;
  }

  const out = new Uint8Array(32);
  const H = [h0, h1, h2, h3, h4, h5, h6, h7];
  for (let i = 0; i < 8; i++) out.set(i32be(H[i]), i * 4);
  return out;
}

// ---------------------- HMAC-SHA256 -----------------
// HMAC(K, M) = SHA256((K' xor opad) || SHA256((K' xor ipad) || M))
// where K' is key padded to 64 bytes (hashed if > 64)

export function makeHmacSha256FnRaw(key) {
  key = toU8(key);
  const block = 64;
  if (key.length > block) key = sha256(key);
  if (key.length < block) {
    const k = new Uint8Array(block);
    k.set(key);
    key = k;
  }
  const ipad = new Uint8Array(block);
  const opad = new Uint8Array(block);
  for (let i = 0; i < block; i++) {
    ipad[i] = key[i] ^ 0x36;
    opad[i] = key[i] ^ 0x5c;
  }
  return (msg) => sha256(concat(opad, sha256(concat(ipad, toU8(msg)))));
}

// public wrapper throws on bad key
export function makeHmacSha256Fn(key) {
  if (key == null || key.length === 0)
    throw new Error("HMAC key must be non-empty");
  const hmac = makeHmacSha256FnRaw(key);
  return (msg) => hmac(msg);
}
