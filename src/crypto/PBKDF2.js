// --------------- PBKDF2-HMAC-SHA256 ------------------
// PBKDF2(P, S, c, dkLen) per RFC 8018 with PRF = HMAC-SHA256
// T_i = U_1 xor U_2 xor ... xor U_c
// U_1 = PRF(P, S || INT_32_BE(i)), U_j = PRF(P, U_{j-1})
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

export function pbkdf2({ password, salt, iterations, dkLen, makeHashFn }) {
  const P = toU8(password);
  const S = toU8(salt);
  if (!Number.isInteger(iterations) || iterations <= 0) {
    throw new Error("iterations must be a positive integer");
  }
  if (!Number.isInteger(dkLen) || dkLen <= 0) {
    throw new Error("dkLen must be a positive integer");
  }

  const hLen = 32; // SHA-256 output size
  const l = Math.ceil(dkLen / hLen);
  const r = dkLen - (l - 1) * hLen;

  const PRF = makeHashFn(P);
  const DK = new Uint8Array(dkLen);
  const blockBuf = new Uint8Array(hLen); // reuse for XOR accumulation

  for (let i = 1; i <= l; i++) {
    // U1 = PRF(P, S || INT(i))
    const U1 = PRF(concat(S, i32be(i)));
    blockBuf.set(U1);
    let Uprev = U1;
    for (let j = 2; j <= iterations; j++) {
      Uprev = PRF(Uprev);
      for (let k = 0; k < hLen; k++) blockBuf[k] ^= Uprev[k];
    }
    const offset = (i - 1) * hLen;
    DK.set(blockBuf.subarray(0, i === l ? r : hLen), offset);
  }
  // Zero sensitive temp buffers (best-effort)
  blockBuf.fill(0);
  return DK;
}
