// Pure JS AES-256-GCM
// No deps. Not constant-time.

// -----------Byte/BigInt utils---------------
const R = 0xe1000000000000000000000000000000n; // reduction for GHASH

function toU8(v) {
  return v instanceof Uint8Array ? v : new Uint8Array(v);
}
function xorBytes(a, b) {
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i];
  return out;
}
function zero(n) {
  return new Uint8Array(n);
}

function bytesToBigIntBE(b) {
  let x = 0n;
  for (let i = 0; i < b.length; i++) x = (x << 8n) | BigInt(b[i]);
  return x;
}
function bigIntToBytesBE(x, len) {
  const out = new Uint8Array(len);
  for (let i = len - 1; i >= 0; i--) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}

// ----------AES primitives-----------
// const S = new Uint8Array([
//   0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe,
//   0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4,
//   0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7,
//   0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3,
//   0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09,
//   0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3,
//   0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe,
//   0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
//   0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92,
//   0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c,
//   0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19,
//   0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
//   0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2,
//   0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5,
//   0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25,
//   0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
//   0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86,
//   0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e,
//   0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42,
//   0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
// ]);
// const Rcon = new Uint8Array([
//   0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
//   0xab, 0x4d, 0x9a,
// ]);

// Base64-decoded S-box and Rcon for compactness. Comments are stripped
const b64ToU8 = (b64) => Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
// S-box
const S = b64ToU8(
  "Y3x3e/Jrb8UwAWcr/terdsqCyX36WUfwrdSir5ykcsC3/ZMmNj/3zDSl5fFx2DEVBMcjwxiWBZoHEoDi6yeydQmDLBobblqgUjvWsynjL4RT0QDtIPyxW2rLvjlKTFjP0O+q+0NNM4VF+QJ/UDyfqFGjQI+SnTj1vLbaIRD/89LNDBPsX5dEF8Snfj1kXRlzYIFP3CIqkIhG7rgU3l4L2+AyOgpJBiRcwtOsYpGV5HnnyDdtjdVOqWxW9Opleq4IunglLhymtMbo3XQfS72LinA+tWZIA/YOYTVXuYbBHZ7h+JgRadmOlJseh+nOVSjfjKGJDb/mQmhBmS0PsFS7Fg=="
);
const Rcon = b64ToU8("AAECBAgQIECAGzZs2KtNmg==");

function rotWord(w) {
  return [w[1], w[2], w[3], w[0]];
}
function subWord(w) {
  return w.map((x) => S[x]);
}

function keyExpand256(key) {
  key = toU8(key);
  if (key.length !== 32) throw new Error("AES-256 key must be 32 bytes");

  const Nk = 8,
    Nb = 4,
    Nr = 14;
  const w = new Uint8Array(Nb * (Nr + 1) * 4);
  w.set(key);
  const temp = [0, 0, 0, 0];
  let bytesGenerated = 32;
  let rconIter = 1;

  while (bytesGenerated < w.length) {
    for (let i = 0; i < 4; i++) temp[i] = w[bytesGenerated - 4 + i];
    if ((bytesGenerated / 4) % Nk === 0) {
      let t = rotWord(temp);
      t = subWord(t);
      t[0] ^= Rcon[rconIter++];
      for (let i = 0; i < 4; i++) temp[i] = t[i];
    } else if ((bytesGenerated / 4) % Nk === 4) {
      let t = subWord(temp);
      for (let i = 0; i < 4; i++) temp[i] = t[i];
    }
    for (let i = 0; i < 4; i++) {
      w[bytesGenerated] = w[bytesGenerated - 32] ^ temp[i];
      bytesGenerated++;
    }
  }
  return w; // 60 words * 4 = 240 bytes (15 round keys incl. initial)
}

function addRoundKey(s, rk, round) {
  for (let c = 0; c < 4; c++) {
    s[0 + 4 * c] ^= rk[round * 16 + 4 * c + 0];
    s[1 + 4 * c] ^= rk[round * 16 + 4 * c + 1];
    s[2 + 4 * c] ^= rk[round * 16 + 4 * c + 2];
    s[3 + 4 * c] ^= rk[round * 16 + 4 * c + 3];
  }
}
function subBytes(s) {
  for (let i = 0; i < 16; i++) s[i] = S[s[i]];
}
function shiftRows(s) {
  const t = s.slice();
  s[1] = t[5];
  s[5] = t[9];
  s[9] = t[13];
  s[13] = t[1];
  s[2] = t[10];
  s[6] = t[14];
  s[10] = t[2];
  s[14] = t[6];
  s[3] = t[15];
  s[7] = t[3];
  s[11] = t[7];
  s[15] = t[11];
}
function xtime(x) {
  return ((x << 1) ^ (x & 0x80 ? 0x1b : 0)) & 0xff;
}
function mixColumns(s) {
  for (let c = 0; c < 4; c++) {
    const i = 4 * c;
    const a0 = s[i],
      a1 = s[i + 1],
      a2 = s[i + 2],
      a3 = s[i + 3];
    const r0 = xtime(a0) ^ (a1 ^ xtime(a1)) ^ a2 ^ a3;
    const r1 = a0 ^ xtime(a1) ^ (a2 ^ xtime(a2)) ^ a3;
    const r2 = a0 ^ a1 ^ xtime(a2) ^ (a3 ^ xtime(a3));
    const r3 = a0 ^ xtime(a0) ^ a1 ^ a2 ^ xtime(a3);
    s[i] = r0 & 0xff;
    s[i + 1] = r1 & 0xff;
    s[i + 2] = r2 & 0xff;
    s[i + 3] = r3 & 0xff;
  }
}
function aesEncryptBlock(rk, block16) {
  const Nr = 14;
  const s = new Uint8Array(block16);
  addRoundKey(s, rk, 0);
  for (let round = 1; round < Nr; round++) {
    subBytes(s);
    shiftRows(s);
    mixColumns(s);
    addRoundKey(s, rk, round);
  }
  subBytes(s);
  shiftRows(s);
  addRoundKey(s, rk, Nr);
  return s;
}

// ---------------GCM components-------------------
function inc32(counter16) {
  const out = counter16.slice();
  // increment last 32 bits as big-endian
  let carry = 1;
  for (let i = 15; i >= 12; i--) {
    const v = (out[i] | 0) + carry;
    out[i] = v & 0xff;
    carry = v >>> 8;
    if (!carry) break;
  }
  return out;
}

// GHASH multiply: Z = X * Y in GF(2^128) with polynomial x^128 + x^7 + x^2 + x + 1.
function ghashMultiply(x128, y128) {
  let Z = 0n;
  let V = y128;
  for (let i = 0; i < 128; i++) {
    const bit = (x128 >> BigInt(127 - i)) & 1n;
    if (bit) Z ^= V;
    if ((V & 1n) === 0n) {
      V >>= 1n;
    } else {
      V = (V >> 1n) ^ R;
    }
  }
  return Z;
}

function ghash(H, A, C) {
  // Pad to 128-bit blocks
  function pad16(u8) {
    const rem = u8.length % 16;
    return rem ? new Uint8Array([...u8, ...new Uint8Array(16 - rem)]) : u8;
  }
  const A_ = pad16(A);
  const C_ = pad16(C);

  let Y = 0n;
  const Hn = bytesToBigIntBE(H);

  for (let off = 0; off < A_.length; off += 16) {
    const Xi = bytesToBigIntBE(A_.subarray(off, off + 16));
    Y = ghashMultiply(Y ^ Xi, Hn);
  }
  for (let off = 0; off < C_.length; off += 16) {
    const Xi = bytesToBigIntBE(C_.subarray(off, off + 16));
    Y = ghashMultiply(Y ^ Xi, Hn);
  }

  const lenBlock = new Uint8Array(16);
  const aBits = BigInt(A.length) * 8n;
  const cBits = BigInt(C.length) * 8n;
  lenBlock.set(bigIntToBytesBE(aBits, 8), 0);
  lenBlock.set(bigIntToBytesBE(cBits, 8), 8);

  Y = ghashMultiply(Y ^ bytesToBigIntBE(lenBlock), Hn);
  return bigIntToBytesBE(Y, 16);
}

function gctr(rk, icb, input) {
  // GCTR per SP800-38D §6.5: XOR with AES_K(inc32^i(ICB))
  if (input.length === 0) return new Uint8Array(0);
  const out = new Uint8Array(input.length);
  let ctr = icb.slice();
  for (let off = 0; off < input.length; off += 16) {
    ctr = inc32(ctr);
    const keystream = aesEncryptBlock(rk, ctr);
    const chunk = input.subarray(off, Math.min(off + 16, input.length));
    for (let i = 0; i < chunk.length; i++) {
      out[off + i] = chunk[i] ^ keystream[i];
    }
  }
  return out;
}

// -----------Public GCM API----------------
export function aes256GcmEncrypt({
  key,
  iv,
  plaintext,
  aad = new Uint8Array(0),
  tagLength = 16,
}) {
  key = toU8(key);
  iv = toU8(iv);
  plaintext = toU8(plaintext);
  aad = toU8(aad);
  if (key.length !== 32) throw new Error("AES-256 key must be 32 bytes");
  if (tagLength !== 16)
    throw new Error("Only 128-bit tags supported in this reference");

  const rk = keyExpand256(key);
  const H = aesEncryptBlock(rk, zero(16)); // hash subkey H = E_K(0^128)

  // Compute J0
  let J0;
  if (iv.length === 12) {
    J0 = new Uint8Array(16);
    J0.set(iv, 0);
    J0[15] = 1; // 0x00000001 appended
  } else {
    const S = ghash(H, new Uint8Array(0), iv);
    J0 = S; // per spec: GHASH(H, {}, IV) when IV not 96-bit
  }

  const ciphertext = gctr(rk, J0, plaintext); // C = GCTR_K(inc32(J0), P) in gctr increments internally
  const S = ghash(H, aad, ciphertext);
  const tag = xorBytes(aesEncryptBlock(rk, J0), S).subarray(0, tagLength);

  return { ciphertext, tag };
}

export function aes256GcmDecrypt({
  key,
  iv,
  ciphertext,
  aad = new Uint8Array(0),
  tag,
}) {
  key = toU8(key);
  iv = toU8(iv);
  ciphertext = toU8(ciphertext);
  aad = toU8(aad);
  tag = toU8(tag);
  if (key.length !== 32) throw new Error("AES-256 key must be 32 bytes");
  if (tag.length !== 16)
    throw new Error("Only 128-bit tags supported in this reference");

  const rk = keyExpand256(key);
  const H = aesEncryptBlock(rk, zero(16));

  let J0;
  if (iv.length === 12) {
    J0 = new Uint8Array(16);
    J0.set(iv, 0);
    J0[15] = 1;
  } else {
    J0 = ghash(H, new Uint8Array(0), iv);
  }

  const S = ghash(H, aad, ciphertext);
  const expectedTag = xorBytes(aesEncryptBlock(rk, J0), S).subarray(
    0,
    tag.length
  );

  // constant-time-ish compare
  if (expectedTag.length !== tag.length) return { ok: false, plaintext: null };
  let diff = 0;
  for (let i = 0; i < tag.length; i++) diff |= expectedTag[i] ^ tag[i];
  if (diff !== 0) return { ok: false, plaintext: null };

  const plaintext = gctr(rk, J0, ciphertext);
  return { ok: true, plaintext };
}
