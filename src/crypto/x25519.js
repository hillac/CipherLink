// Pure JS X25519 (Curve25519 Montgomery) key exchange
// No deps. Not constant-time.

// -----------Byte/BigInt utils---------------
const U8 = (v) => (v instanceof Uint8Array ? v : new Uint8Array(v));
const zero = (n) => new Uint8Array(n);

function leBytesToBigInt(b) {
  b = U8(b);
  let x = 0n;
  for (let i = b.length - 1; i >= 0; i--) x = (x << 8n) | BigInt(b[i]);
  return x;
}
function bigIntToLeBytes(x, len = 32) {
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}

// -------------- Field arithmetic mod p = 2^255 - 19 --------------
const P = (1n << 255n) - 19n;
const A24 = 121666n; // (486662 + 2)/4 per RFC 7748

function mod(a) {
  a %= P;
  return a < 0n ? a + P : a;
}
function add(a, b) {
  return mod(a + b);
}
function sub(a, b) {
  return mod(a - b);
}
function mul(a, b) {
  return mod(a * b);
}
function sqr(a) {
  return mod(a * a);
}
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
function inv(a) {
  // a^(p-2) mod p (Fermat's little theorem)
  return powMod(a, P - 2n);
}

// -------------- Montgomery ladder (RFC 7748) --------------
function x25519ScalarMultRaw(nLE32, uLE32) {
  // Inputs are 32-byte little-endian
  const x1 = leBytesToBigInt(U8(uLE32));

  let x2 = 1n;
  let z2 = 0n;
  let x3 = x1;
  let z3 = 1n;
  let swap = 0n;

  // Interpret scalar as integer
  let k = leBytesToBigInt(U8(nLE32));

  for (let t = 254; t >= 0; t--) {
    const kt = (k >> BigInt(t)) & 1n;
    swap ^= kt;

    // Conditional swap (not constant-time in JS BigInt)
    if (swap) {
      [x2, x3] = [x3, x2];
      [z2, z3] = [z3, z2];
    }
    swap = kt;

    const A = add(x2, z2);
    const B = sub(x2, z2);
    const AA = sqr(A);
    const BB = sqr(B);
    const E = sub(AA, BB);
    const C = add(x3, z3);
    const D = sub(x3, z3);
    const DA = mul(D, A);
    const CB = mul(C, B);
    x3 = sqr(add(DA, CB));
    z3 = mul(x1, sqr(sub(DA, CB)));
    x2 = mul(AA, BB);
    z2 = mul(E, add(AA, mul(A24, E)));
  }
  // Final conditional swap
  if (swap) {
    [x2, x3] = [x3, x2];
    [z2, z3] = [z3, z2];
  }

  const z2Inv = inv(z2);
  const res = mod(mul(x2, z2Inv));
  return bigIntToLeBytes(res, 32);
}

// -------------- Clamp & helpers --------------
function clampScalar(sk) {
  sk = U8(sk);
  if (sk.length !== 32) throw new Error("X25519 scalar must be 32 bytes");
  const s = new Uint8Array(sk);
  s[0] &= 248;
  s[31] &= 127;
  s[31] |= 64;
  return s;
}

function getRandomBytes(n) {
  const out = new Uint8Array(n);
  crypto.getRandomValues(out);
  return out;
}

// -------------- Public API --------------
export function x25519(privateKey, publicU) {
  // privateKey: 32-byte little-endian scalar (will be clamped)
  // publicU: 32-byte little-endian u-coordinate (peer public)
  const n = clampScalar(privateKey);
  const u = U8(publicU);
  if (u.length !== 32)
    throw new Error("X25519 public u-coordinate must be 32 bytes");
  return x25519ScalarMultRaw(n, u); // 32-byte shared secret (little-endian)
}

export function generateKeyPair(seed32) {
  // Optional: deterministic from 32-byte seed (like libsodium's crypto_box_seed_keypair)
  // If seed not given, use RNG.
  const seed = seed32 ? U8(seed32) : getRandomBytes(32);
  if (seed.length !== 32) throw new Error("Seed must be 32 bytes");

  const sk = clampScalar(seed);
  const base = new Uint8Array(32);
  base[0] = 9; // base point u = 9, little-endian
  const pk = x25519(sk, base);
  return { privateKey: sk, publicKey: pk };
}

export function deriveSharedSecret(myPrivateKey, theirPublicKey) {
  // Returns 32-byte Uint8Array (little-endian)
  // If all-zero output, peer's public key was invalid (small subgroup); caller should check.
  const ss = x25519(myPrivateKey, theirPublicKey);
  return ss;
}
