// tests-aes256gcm.mjs
import { aes256GcmDecrypt, aes256GcmEncrypt } from "./aes256gcm.js";
import { pbkdf2Sha256, pbkdf2Sha256Hex, sha256 } from "./PBKDF2.js";
import { x25519, generateKeyPair, deriveSharedSecret } from "./x25519.js";

// ---------- helpers ----------
const hex = (u8) =>
  [...u8].map((b) => b.toString(16).padStart(2, "0")).join("");
const u8 = (hexStr) =>
  new Uint8Array(hexStr.match(/../g).map((h) => parseInt(h, 16)));
const enc = new TextEncoder();

const eq = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);

const clone = (u) => new Uint8Array(u); // shallow copy of bytes

// Simple deterministic byte generator
function deterministicBytes(len, seed = 1) {
  // LCG params
  let x = seed >>> 0;
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    x = (1664525 * x + 1013904223) >>> 0;
    out[i] = x & 0xff;
  }
  return out;
}

// Pick WebCrypto subtle (browser or Node)
const subtle =
  globalThis.crypto?.subtle ?? (await import("node:crypto")).webcrypto.subtle;

// Split ct||tag from WebCrypto into [ct, tag]
function splitCtTag(buf, tagBytes = 16) {
  const all = new Uint8Array(buf);
  const ct = all.subarray(0, all.length - tagBytes);
  const tag = all.subarray(all.length - tagBytes);
  return [ct, tag];
}

// Assert helper
function assert(cond, message) {
  if (!cond) throw new Error(message);
}

// ---------- test cases aes ----------
// key: 32 bytes (AES-256)
// iv : 12 bytes
// aad: Uint8Array | undefined (both provided and omitted covered)
// pt : Uint8Array plaintext

const aes256gcmcases = [
  {
    name: "sample",
    key: u8("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
    iv: u8("1af38c2dc2b96ffdd86694092341bc04"),
    aad: u8("feedfacedeadbeeffeedfacedeadbeefabaddad2"),
    pt: u8(
      "d9313225f88406e5a55909c5aff5269a" +
        "86a7a9531534f7da2e4c303d8a318a72" +
        "1c3c0c95956809532fcf0e2449a6b525" +
        "b16aedf5aa0de657ba637b39"
    ),
  },
  {
    name: "Empty plaintext, non-empty AAD",
    key: deterministicBytes(32, 2),
    iv: deterministicBytes(12, 3),
    aad: deterministicBytes(37, 4),
    pt: new Uint8Array([]),
  },
  {
    name: "Short plaintext (1 byte), empty AAD",
    key: deterministicBytes(32, 5),
    iv: deterministicBytes(12, 6),
    aad: new Uint8Array([]),
    pt: new Uint8Array([0x42]),
  },
  {
    name: "Short plaintext (2 bytes), no AAD (undefined)",
    key: deterministicBytes(32, 7),
    iv: deterministicBytes(12, 8),
    aad: undefined, // tests optional AAD path
    pt: new Uint8Array([0x00, 0xff]),
  },
  {
    name: "UTF-8 text (multibyte), with AAD",
    key: deterministicBytes(32, 9),
    iv: deterministicBytes(12, 10),
    aad: enc.encode("associated data ✓"),
    pt: enc.encode("hello – こんにちは – 👍"),
  },
  {
    name: "Medium plaintext (4 KiB), empty AAD",
    key: deterministicBytes(32, 11),
    iv: deterministicBytes(12, 12),
    aad: new Uint8Array([]),
    pt: deterministicBytes(4096, 13),
  },
  {
    name: "Long plaintext (64 KiB), non-empty AAD",
    key: deterministicBytes(32, 14),
    iv: deterministicBytes(12, 15),
    aad: deterministicBytes(128, 16),
    pt: deterministicBytes(65536, 17),
  },
];

async function runOneaes256gcm(tc) {
  // Keep original inputs for mutation checks
  const key0 = clone(tc.key);
  const iv0 = clone(tc.iv);
  const aad0 = tc.aad === undefined ? undefined : clone(tc.aad);
  const pt0 = clone(tc.pt);

  // 1) Pure JS encrypt
  const { ciphertext, tag } = aes256GcmEncrypt({
    key: tc.key,
    iv: tc.iv,
    plaintext: tc.pt,
    aad: tc.aad,
  });

  // 1a) Pure JS decrypt (should be identity)
  const dec = aes256GcmDecrypt({
    key: tc.key,
    iv: tc.iv,
    ciphertext,
    aad: tc.aad,
    tag,
  });

  assert(dec.ok, `[${tc.name}] aes256GcmDecrypt returned ok=false`);
  assert(
    eq(dec.plaintext, tc.pt),
    `[${tc.name}] decrypt != original plaintext`
  );

  // 2) SubtleCrypto comparison (ct/tag must match exactly)
  const cryptoKey = await subtle.importKey(
    "raw",
    tc.key,
    { name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"]
  );

  const subtleCtBuf = await subtle.encrypt(
    {
      name: "AES-GCM",
      iv: tc.iv,
      additionalData: tc.aad, // can be undefined or empty
      tagLength: 128,
    },
    cryptoKey,
    tc.pt
  );

  const [subtleCt, subtleTag] = splitCtTag(subtleCtBuf, 16);

  assert(
    eq(ciphertext, subtleCt),
    `[${tc.name}] ciphertext mismatch vs SubtleCrypto`
  );
  assert(eq(tag, subtleTag), `[${tc.name}] tag mismatch vs SubtleCrypto`);

  // 2a) SubtleCrypto decrypt of our (ct||tag)
  const subtlePtBuf = await subtle.decrypt(
    {
      name: "AES-GCM",
      iv: tc.iv,
      additionalData: tc.aad,
      tagLength: 128,
    },
    cryptoKey,
    new Uint8Array([...ciphertext, ...tag])
  );
  assert(
    eq(new Uint8Array(subtlePtBuf), tc.pt),
    `[${tc.name}] SubtleCrypto decrypt of our ct||tag failed`
  );

  // 3) Input immutability checks
  assert(eq(tc.key, key0), `[${tc.name}] key mutated`);
  assert(eq(tc.iv, iv0), `[${tc.name}] iv mutated`);
  if (tc.aad !== undefined)
    assert(eq(tc.aad, aad0), `[${tc.name}] aad mutated`);
  assert(eq(tc.pt, pt0), `[${tc.name}] plaintext mutated`);

  return {
    name: tc.name,
    ciphertextHex: hex(ciphertext),
    tagHex: hex(tag),
    ptLen: tc.pt.length,
    aadLen: tc.aad?.length ?? 0,
  };
}

// ------------- SHA-256 cases ------------------
const sha256Cases = [
  {
    name: "Empty message",
    msg: new Uint8Array([]),
  },
  {
    name: "Short ASCII",
    msg: enc.encode("abc"),
  },
  {
    name: "Unicode text",
    msg: enc.encode("hello – こんにちは – 👍"),
  },
  {
    name: "1 KiB deterministic",
    msg: deterministicBytes(1024, 7),
  },
  {
    name: "64 KiB deterministic",
    msg: deterministicBytes(65536, 9),
  },
];

async function runOneSha256(tc) {
  const msg0 = clone(tc.msg);

  // Our SHA-256
  const ours = sha256(tc.msg);

  // WebCrypto digest
  const theirsBuf = await subtle.digest("SHA-256", tc.msg);
  const theirs = new Uint8Array(theirsBuf);

  if (!eq(ours, theirs)) {
    throw new Error(
      `[${tc.name}] digest mismatch\nours:   ${hex(ours)}\ntheirs: ${hex(
        theirs
      )}`
    );
  }

  // Input immutability
  if (!eq(tc.msg, msg0)) throw new Error(`[${tc.name}] message mutated`);

  return { name: tc.name, digestHex: hex(ours), len: tc.msg.length };
}

// --------------- PBKDF2-HMAC-SHA256 cases -------------------------

const pbkdf2Cases = [
  {
    name: "RFC-style: password/salt, 1 iter, 32B",
    password: enc.encode("password"),
    salt: enc.encode("salt"),
    iterations: 1,
    dkLen: 32,
  },
  {
    name: "Basic: 1000 iters, 32B",
    password: enc.encode("password"),
    salt: enc.encode("salt"),
    iterations: 1000,
    dkLen: 32,
  },
  {
    name: "Empty password, empty salt, 2 iters, 16B",
    password: new Uint8Array([]),
    salt: new Uint8Array([]),
    iterations: 2,
    dkLen: 16,
  },
  {
    name: "Unicode P/S, 10k iters, 48B (non-multiple of 32)",
    password: enc.encode("pāsswörd🔒"),
    salt: enc.encode("sālty🧂"),
    iterations: 10000,
    dkLen: 48,
  },
  {
    name: "Deterministic bytes, 4096 iters, 1B (tiny dkLen)",
    password: deterministicBytes(33, 11), // longer than block
    salt: deterministicBytes(17, 12),
    iterations: 4096,
    dkLen: 1,
  },
  {
    name: "Deterministic bytes, 8 iters, 63B",
    password: deterministicBytes(64, 13),
    salt: deterministicBytes(31, 14),
    iterations: 8,
    dkLen: 63,
  },
];

async function runOnePbkdf2(tc) {
  // Preserve originals for immutability checks
  const p0 = clone(tc.password);
  const s0 = clone(tc.salt);

  // Our PBKDF2
  const ours = pbkdf2Sha256({
    password: tc.password,
    salt: tc.salt,
    iterations: tc.iterations,
    dkLen: tc.dkLen,
  });

  // WebCrypto PBKDF2
  const key = await subtle.importKey(
    "raw",
    tc.password,
    { name: "PBKDF2" },
    false,
    ["deriveBits"]
  );
  const theirsBuf = await subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: tc.salt,
      iterations: tc.iterations,
      hash: "SHA-256",
    },
    key,
    tc.dkLen * 8
  );
  const theirs = new Uint8Array(theirsBuf);

  if (!eq(ours, theirs)) {
    throw new Error(
      `[${tc.name}] PBKDF2 mismatch\nours:   ${hex(ours)}\ntheirs: ${hex(
        theirs
      )}`
    );
  }

  // Immutability
  if (!eq(tc.password, p0)) throw new Error(`[${tc.name}] password mutated`);
  if (!eq(tc.salt, s0)) throw new Error(`[${tc.name}] salt mutated`);

  // Also sanity-check hex helper path
  const oursHex = pbkdf2Sha256Hex({
    password: tc.password,
    salt: tc.salt,
    iterations: tc.iterations,
    dkLen: tc.dkLen,
  });
  if (oursHex !== hex(ours)) {
    throw new Error(`[${tc.name}] hex helper mismatch`);
  }

  return {
    name: tc.name,
    dkLen: tc.dkLen,
    iterations: tc.iterations,
    dkHex: hex(ours),
  };
}

// --------------- PBKDF2-HMAC-SHA256 + AES 256 GCM integration -------------------------

const pbkdfAESCases = [
  {
    name: "password and cipher encryption",
    password: "testpassword",
    salt: enc.encode("testsalt"),
    iterations: 10_000,
    dkLen: 32,
    iv: deterministicBytes(12, 1234),
    aad: enc.encode("headerdata"),
    pt: enc.encode("This is a secret message."),
  },
  {
    name: "long message with empty AAD",
    password: "anotherpassword",
    salt: enc.encode("anothersalt"),
    iterations: 50_000,
    dkLen: 32,
    iv: deterministicBytes(12, 5678),
    aad: new Uint8Array([]),
    pt: deterministicBytes(10_000, 91011),
  },
];

async function runOnePbkdfAes(tc) {
  // Derive key
  const key = pbkdf2Sha256({
    password: enc.encode(tc.password),
    salt: tc.salt,
    iterations: tc.iterations,
    dkLen: tc.dkLen,
  });

  // Encrypt
  const { ciphertext, tag } = aes256GcmEncrypt({
    key,
    iv: tc.iv,
    plaintext: tc.pt,
    aad: tc.aad,
  });

  // Decrypt
  const dec = aes256GcmDecrypt({
    key,
    iv: tc.iv,
    ciphertext,
    aad: tc.aad,
    tag,
  });

  assert(dec.ok, `[${tc.name}] Decryption failed`);
  assert(
    eq(dec.plaintext, tc.pt),
    `[${tc.name}] Decrypted plaintext does not match original`
  );

  return {
    name: tc.name,
    ciphertextHex: hex(ciphertext),
    tagHex: hex(tag),
  };
}

// ---------- X25519 tests ----------
//
// Assumes you have the following in scope from your test harness:
//   - hex(u8) helpers
//   - deterministicBytes(len, seed)
//   - subtle (WebCrypto SubtleCrypto)
//   - assert(cond, message)
//   - eq(a,b)
// And the X25519 implementation you wrote:
//   - x25519(privateKey32, publicU32)
//   - generateKeyPair(seed32?)  // returns { privateKey, publicKey }
//   - deriveSharedSecret(myPrivateKey32, theirPublicKey32)

// Basepoint u = 9 (little-endian)
const X25519_BASE = (() => {
  const b = new Uint8Array(32);
  b[0] = 9;
  return b;
})();

async function subtleImportX25519Private(raw32) {
  // Some runtimes only accept 'raw' for X25519 private keys; others accept JWK/PKCS8.
  // We first try 'raw', fallback to 'pkcs8' (not provided here).
  try {
    return await subtle.importKey("raw", raw32, { name: "X25519" }, false, [
      "deriveBits",
    ]);
  } catch (e) {
    throw new Error(`Subtle import private failed: ${e.message ?? e}`);
  }
}
async function subtleImportX25519Public(raw32) {
  try {
    return await subtle.importKey("raw", raw32, { name: "X25519" }, false, []);
  } catch (e) {
    throw new Error(`Subtle import public failed: ${e.message ?? e}`);
  }
}
async function subtleDeriveX25519(privateRaw32, publicRaw32) {
  const priv = await subtleImportX25519Private(privateRaw32);
  const pub = await subtleImportX25519Public(publicRaw32);
  const bits = await subtle.deriveBits(
    { name: "X25519", public: pub },
    priv,
    256
  );
  return new Uint8Array(bits); // 32 bytes
}

// RFC 7748 §5.2 vectors (little-endian hex)
const RFC_SCALAR = u8(
  "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
);
const RFC_PUBLIC = u8(
  "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
);
const RFC_PEER_PUBLIC = u8(
  "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
);
const RFC_SHARED = u8(
  "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
);

// Some edge-case/malicious public keys (encoded u-coordinate)
const ALL_ZERO_PUB = new Uint8Array(32); // small-subgroup / invalid: yields all-zero shared secret

// Build a few deterministic pairs
function detKeyPair(seedA, seedB) {
  const a = generateKeyPair(deterministicBytes(32, seedA));
  const b = generateKeyPair(deterministicBytes(32, seedB));
  return { a, b };
}

// Test cases for X25519
const x25519Cases = [
  // --- RFC known-answer tests ---
  {
    name: "RFC7748 scalar*base → public",
    kind: "scalar-mult",
    scalar: RFC_SCALAR,
    u: X25519_BASE,
    wantU: RFC_PUBLIC,
  },
  {
    name: "RFC7748 ECDH shared secret",
    kind: "derive-shared-rfc",
    // Alice's private = RFC_SCALAR, peer public = RFC_PEER_PUBLIC -> shared
    aPriv: RFC_SCALAR,
    bPub: RFC_PEER_PUBLIC,
    wantShared: RFC_SHARED,
  },

  // --- Deterministic ECDH cross-checks (ours vs SubtleCrypto) ---
  ...[1, 2, 3, 4, 5].map((i) => {
    const seedA = 100 + i;
    const seedB = 200 + i;
    const { a, b } = detKeyPair(seedA, seedB);
    return {
      name: `Deterministic ECDH pair #${i}`,
      kind: "derive-shared",
      aPriv: a.privateKey,
      aPub: a.publicKey,
      bPriv: b.privateKey,
      bPub: b.publicKey,
    };
  }),

  // --- Roundtrip scalar mult with random base 'u' (still compare to subtle) ---
  ...[11, 12, 13].map((i) => ({
    name: `ScalarMult random-u #${i}`,
    kind: "scalar-vs-subtle",
    scalar: deterministicBytes(32, 300 + i), // unclamped: function clamps internally
    u: deterministicBytes(32, 400 + i), // random u-coordinate (not necessarily canonical)
  })),

  // --- Malicious / invalid inputs ---
  {
    name: "All-zero public u-coordinate (small-subgroup) → all-zero shared",
    kind: "small-subgroup",
    aSeed: 555,
    bPub: ALL_ZERO_PUB,
  },
  {
    name: "Wrong private length (31 bytes)",
    kind: "bad-input-ours-and-subtle",
    aPrivBad: deterministicBytes(31, 777),
    bPub: X25519_BASE,
  },
  {
    name: "Wrong public length (33 bytes)",
    kind: "bad-input-ours-and-subtle",
    aPrivBad: deterministicBytes(32, 778),
    bPub: new Uint8Array([...deterministicBytes(33, 779)]),
  },
  {
    name: "Empty inputs",
    kind: "bad-input-ours-and-subtle",
    aPrivBad: new Uint8Array([]),
    bPub: new Uint8Array([]),
  },

  // --- Behavior checks: immutability & keypair public = scalar*base ---
  {
    name: "generateKeyPair public equals x25519(sk, base); inputs immutable",
    kind: "keypair-public-match",
    seed: 999,
  },
];

// Runner
async function runOneX25519(tc) {
  switch (tc.kind) {
    case "scalar-mult": {
      const s0 = clone(tc.scalar);
      const u0 = clone(tc.u);
      const got = x25519(tc.scalar, tc.u);
      assert(eq(got, tc.wantU), `[${tc.name}] scalar*base mismatch`);
      assert(eq(tc.scalar, s0), `[${tc.name}] scalar mutated`);
      assert(eq(tc.u, u0), `[${tc.name}] u mutated`);

      // Compare vs SubtleCrypto for scalar*base by deriving shared with base private (not directly available).
      // Instead, we validate that our public equals subtle's by checking ECDH consistency:
      // Subtle: deriveBits(sk, basePub) == deriveBits(baseSk, pub). We'll synthesize basePub=base*sk via ours,
      // then compare subtle derived shared in the next test types. Here, RFC vector suffices.
      return { name: tc.name, uHex: hex(got) };
    }
    case "derive-shared-rfc": {
      const got = deriveSharedSecret(tc.aPriv, tc.bPub);
      assert(eq(got, tc.wantShared), `[${tc.name}] shared mismatch vs RFC`);

      // Also compare to SubtleCrypto
      const subtleSS = await subtleDeriveX25519(tc.aPriv, tc.bPub);
      assert(eq(got, subtleSS), `[${tc.name}] mismatch vs SubtleCrypto`);

      return { name: tc.name, sharedHex: hex(got) };
    }
    case "derive-shared": {
      // Our side
      const aPubCalc = x25519(tc.aPriv, X25519_BASE);
      const bPubCalc = x25519(tc.bPriv, X25519_BASE);
      assert(
        eq(aPubCalc, tc.aPub) && eq(bPubCalc, tc.bPub),
        `[${tc.name}] public mismatch vs x25519(sk, base)`
      );

      const ssAB = deriveSharedSecret(tc.aPriv, tc.bPub);
      const ssBA = deriveSharedSecret(tc.bPriv, tc.aPub);
      assert(eq(ssAB, ssBA), `[${tc.name}] shared secrets differ (ours)`);

      // SubtleCrypto cross-check both directions
      const subtleAB = await subtleDeriveX25519(tc.aPriv, tc.bPub);
      const subtleBA = await subtleDeriveX25519(tc.bPriv, tc.aPub);
      assert(eq(ssAB, subtleAB), `[${tc.name}] ours vs SubtleCrypto (A)->(B)`);
      assert(eq(ssBA, subtleBA), `[${tc.name}] ours vs SubtleCrypto (B)->(A)`);

      return { name: tc.name, sharedHex: hex(ssAB) };
    }
    case "scalar-vs-subtle": {
      const s0 = clone(tc.scalar);
      const u0 = clone(tc.u);

      // Our scalar mult
      const ours = x25519(tc.scalar, tc.u);

      // Subtle deriveBits: emulate scalar mult as deriveBits(sk, point)
      // For deriveBits, 'privateRaw' is the scalar (clamped by WebCrypto internally),
      // and 'publicRaw' is the u-coordinate point (32 bytes).
      let subtleOK = true;
      let subtleRes;
      try {
        subtleRes = await subtleDeriveX25519(tc.scalar, tc.u);
      } catch (e) {
        subtleOK = false;
      }

      if (subtleOK) {
        assert(eq(ours, subtleRes), `[${tc.name}] mismatch vs SubtleCrypto`);
      } else {
        // Some engines reject non-canonical u; accept as long as our code returned 32 bytes
        assert(ours.length === 32, `[${tc.name}] expected 32-byte output`);
      }

      assert(eq(tc.scalar, s0), `[${tc.name}] scalar mutated`);
      assert(eq(tc.u, u0), `[${tc.name}] u mutated`);
      return { name: tc.name, outHex: hex(ours) };
    }
    case "small-subgroup": {
      const a = generateKeyPair(deterministicBytes(32, tc.aSeed));
      const ours = deriveSharedSecret(a.privateKey, tc.bPub);
      // For all-zero public, X25519 shared must be all-zero
      const zero32 = new Uint8Array(32);
      assert(eq(ours, zero32), `[${tc.name}] expected all-zero shared (ours)`);

      // Subtle: some implementations return zero; others may reject the key.
      let subtleOK = true;
      let subtleRes;
      try {
        subtleRes = await subtleDeriveX25519(a.privateKey, tc.bPub);
        assert(
          eq(subtleRes, zero32),
          `[${tc.name}] SubtleCrypto expected all-zero shared`
        );
      } catch {
        // Accept rejection as valid behavior in this negative test
        subtleOK = false;
      }
      return { name: tc.name, subtleAccepted: subtleOK };
    }
    case "bad-input-ours-and-subtle": {
      // Expect both our implementation and SubtleCrypto to reject
      let oursThrew = false;
      try {
        // Try to run something that requires both keys
        x25519(tc.aPrivBad, tc.bPub);
      } catch {
        oursThrew = true;
      }
      assert(oursThrew, `[${tc.name}] our x25519 should throw`);

      let subtleThrew = false;
      try {
        await subtleDeriveX25519(tc.aPrivBad, tc.bPub);
      } catch {
        subtleThrew = true;
      }
      assert(subtleThrew, `[${tc.name}] SubtleCrypto should throw`);

      return { name: tc.name, oursThrew, subtleThrew };
    }
    case "keypair-public-match": {
      const seed = deterministicBytes(32, tc.seed);
      const seed0 = clone(seed);
      const { privateKey, publicKey } = generateKeyPair(seed);

      const expectedPub = x25519(privateKey, X25519_BASE);
      assert(
        eq(publicKey, expectedPub),
        `[${tc.name}] publicKey != x25519(sk, base)`
      );

      // Immutability: ensure seed passed in wasn't mutated
      assert(eq(seed, seed0), `[${tc.name}] input seed mutated`);

      // Subtle cross-check: derive with (sk, base) equals x25519(sk, base)
      const subtlePubViaDerive = await subtleDeriveX25519(
        privateKey,
        X25519_BASE
      );
      assert(
        eq(subtlePubViaDerive, publicKey),
        `[${tc.name}] public mismatch vs SubtleCrypto`
      );

      return { name: tc.name, pubHex: hex(publicKey) };
    }
    default:
      throw new Error(`Unknown test kind: ${tc.kind}`);
  }
}

// ---------- runner -----------

const tests = [
  { name: "AES-256-GCM", cases: aes256gcmcases, runner: runOneaes256gcm },
  { name: "SHA-256", cases: sha256Cases, runner: runOneSha256 },
  { name: "PBKDF2-HMAC-SHA256", cases: pbkdf2Cases, runner: runOnePbkdf2 },
  {
    name: "PBKDF2 + AES-256-GCM Integration",
    cases: pbkdfAESCases,
    runner: runOnePbkdfAes,
  },
  { name: "X25519", cases: x25519Cases, runner: runOneX25519 },
];

async function runAll() {
  let totalFailed = 0;
  for (const testGroup of tests) {
    console.log(`\n=== ${testGroup.name} tests ===`);
    let failed = 0;
    for (const tc of testGroup.cases) {
      try {
        const r = await testGroup.runner(tc);
        console.log(`[PASS] ${tc.name}`);
      } catch (e) {
        failed++;
        console.error(`[FAIL] ${tc.name}: ${e.message}`);
      }
    }
    const passed = testGroup.cases.length - failed;
    totalFailed += failed;
    console.log(
      `\n${testGroup.name} Summary: ${passed}/${testGroup.cases.length} passed`
    );
  }
  console.log("\n=== Overall Summary ===");
  if (totalFailed === 0) {
    console.log("All tests passed!");
  } else {
    console.log(`${totalFailed} test(s) failed.`);
    throw new Error("Some tests failed");
  }
}

runAll().catch((e) => {
  console.error(e);
  process.exit(1);
});
