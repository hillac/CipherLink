// ----- Field constants -----
const P = (1n << 255n) - 19n; // 2^255 - 19
const A24 = 121665n; // (486662 - 2) / 4

// ----- Little-endian helpers -----
export function leBytesToBigInt(le) {
  let x = 0n;
  for (let i = le.length - 1; i >= 0; i--) {
    x = (x << 8n) | BigInt(le[i]);
  }
  return x;
}

export function bigIntToLeBytes(x, len = 32) {
  const out = new Uint8Array(len);
  let v = x;
  for (let i = 0; i < len; i++) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

// ----- Scalar clamping (RFC 7748 §5) -----
function clampScalar(k) {
  const s = new Uint8Array(k); // copy
  s[0] &= 248;
  s[31] &= 127;
  s[31] |= 64;
  return s;
}

// ----- Modular arithmetic helpers -----
const mod = (a) => {
  a %= P;
  return a >= 0n ? a : a + P;
};

const add = (a, b) => mod(a + b);
const sub = (a, b) => mod(a - b);
const mul = (a, b) => mod(a * b);
const sqr = (a) => mod(a * a);

function powMod(base, exp) {
  base = mod(base);
  let result = 1n;
  while (exp > 0n) {
    if (exp & 1n) result = mod(result * base);
    base = mod(base * base);
    exp >>= 1n;
  }
  return result;
}

// Inverse via Fermat: a^(p-2) mod p
const inv = (a) => powMod(a, P - 2n);

function isAllZero32(u8) {
  // Constant-time-ish: OR-reduce all bytes, avoid early returns.
  let acc = 0;
  for (let i = 0; i < 32; i++) acc |= u8[i];
  return acc === 0;
}

// Conditional swap (constant-time ish in JS;)
function cswap(cond, x2, x3) {
  if (cond !== 0n && cond !== 1n)
    throw new Error("cswap: cond must be 0n or 1n");
  const mask = -cond; // 0n -> 0, 1n -> ...1111b (two's complement)
  const tx = (x2 ^ x3) & mask;
  return [x2 ^ tx, x3 ^ tx];
}

/**
 * montgomeryLadder(scalarBytes, uBytes)
 * - scalarBytes: Uint8Array(32) (raw private scalar; function will clamp)
 * - uBytes: Uint8Array(32) u-coordinate, little-endian
 * Returns: Uint8Array(32) u-coordinate result
 */
function montgomeryLadder(scalarBytes, uBytes) {
  const k = leBytesToBigInt(clampScalar(scalarBytes));
  // Decode u-coordinate (mask MSB when receiving per RFC §5)
  const uLE = new Uint8Array(uBytes);
  uLE[31] &= 0x7f;
  const x1 = mod(leBytesToBigInt(uLE));

  // Initialize ladder
  let x2 = 1n,
    z2 = 0n;
  let x3 = x1,
    z3 = 1n;
  let swap = 0n;

  for (let t = 254; t >= 0; t--) {
    const kt = (k >> BigInt(t)) & 1n;
    swap ^= kt;
    [x2, x3] = cswap(swap, x2, x3);
    [z2, z3] = cswap(swap, z2, z3);
    swap = kt;

    const A = add(x2, z2);
    const AA = sqr(A);
    const B = sub(x2, z2);
    const BB = sqr(B);
    const E = sub(AA, BB);
    const C = add(x3, z3);
    const D = sub(x3, z3);
    const DA = mul(D, A);
    const CB = mul(C, B);
    const x3n = sqr(add(DA, CB));
    const z3n = mul(x1, sqr(sub(DA, CB)));
    const x2n = mul(AA, BB);
    const z2n = mul(E, add(AA, mul(A24, E)));

    x3 = x3n;
    z3 = z3n;
    x2 = x2n;
    z2 = z2n;
  }

  [x2, x3] = cswap(swap, x2, x3);
  [z2, z3] = cswap(swap, z2, z3);

  const res = mul(x2, inv(z2));
  return bigIntToLeBytes(res, 32);
}

const assertU832 = (arr, name) => {
  if (!(arr instanceof Uint8Array) || arr.length !== 32) {
    throw new Error(`${name} must be Uint8Array(32)`);
  }
};

export function x25519(scalar, u) {
  assertU832(scalar, "scalar");
  assertU832(u, "u");
  return montgomeryLadder(scalar, u);
}

export function sharedKey(secretKey, publicKey) {
  const ss = x25519(secretKey, publicKey);
  if (isAllZero32(ss)) {
    throw new Error("The operation failed for an operation-specific reason");
  }
  return ss;
}

export function generateKeyPair() {
  const secretKey = crypto.getRandomValues(new Uint8Array(32));
  const clamped = clampScalar(secretKey);
  const basePoint = new Uint8Array(32);
  basePoint[0] = 9; // u = 9 (§4.1)
  const publicKey = x25519(clamped, basePoint);
  return { publicKey, secretKey: clamped };
}
