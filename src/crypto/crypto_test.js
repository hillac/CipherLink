// tests-aes256gcm.mjs
import { aes256GcmDecrypt, aes256GcmEncrypt } from "./aes256gcm.js";
import {
  pbkdf2Sha256,
  pbkdf2Sha256Hex,
  sha256,
  makeHmacSha256Fn,
} from "./PBKDF2.js";
import { x25519, generateKeyPair, sharedKey } from "./x25519.js";

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

// ------------- HMAC-SHA256 cases ------------------

const hmacSha256Cases = [
  {
    name: "RFC-style: key/message",
    key: enc.encode("key"),
    msg: enc.encode("The quick brown fox jumps over the lazy dog"),
  },
  {
    name: "Empty key",
    key: new Uint8Array([]),
    msg: enc.encode("Some message"),
    expectThrows: true,
  },
  {
    name: 'Key and empty message ("test key")',
    key: enc.encode("test key"),
    msg: new Uint8Array([]),
  },
  {
    name: "Unicode key/message",
    key: enc.encode("sēkrēt🔑"),
    msg: enc.encode("mēssāgē📧"),
  },
  {
    name: "Deterministic bytes key/message",
    key: deterministicBytes(50, 11),
    msg: deterministicBytes(100, 12),
  },
];

async function runOneHmacSha256(tc) {
  const key0 = clone(tc.key);
  const msg0 = clone(tc.msg);
  // Our HMAC-SHA256
  let ours;
  try {
    ours = makeHmacSha256Fn(tc.key)(tc.msg);
  } catch (e) {
    if (tc.expectThrows) return;
    throw e;
  }
  // WebCrypto HMAC
  const cryptoKey = await subtle.importKey(
    "raw",
    tc.key,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const theirsBuf = await subtle.sign("HMAC", cryptoKey, tc.msg);
  const theirs = new Uint8Array(theirsBuf);
  if (!eq(ours, theirs)) {
    throw new Error(
      `[${tc.name}] HMAC-SHA256 mismatch\nours:   ${hex(ours)}\ntheirs: ${hex(
        theirs
      )}`
    );
  }

  // Immutability
  if (!eq(tc.key, key0)) throw new Error(`[${tc.name}] key mutated`);
  if (!eq(tc.msg, msg0)) throw new Error(`[${tc.name}] message mutated`);
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

// ---------- X25519 tests----------

function runOneX25519GetSameKey() {
  const alice = generateKeyPair();
  const bob = generateKeyPair();

  // serialise
  const alicePub = hex(clone(alice.publicKey));
  const bobPub = hex(clone(bob.publicKey));

  //deserialise
  const alicePub2 = u8(alicePub);
  const bobPub2 = u8(bobPub);

  // exchange
  const aliceSecret = sharedKey(alice.secretKey, bobPub2);
  const bobSecret = sharedKey(bob.secretKey, alicePub2);

  assert(
    eq(aliceSecret, bobSecret),
    `X25519 derived shared secrets do not match`
  );
}

async function runOneX25519MatchesSubtle() {
  const subtle = crypto.subtle;
  const aliceKeyPair = await subtle.generateKey({ name: "X25519" }, true, [
    "deriveBits",
  ]);
  const rawAlicePublicKey = await subtle.exportKey(
    "raw",
    aliceKeyPair.publicKey
  );

  const bobKeyPair = generateKeyPair();
  const subtleImportBobPub = await subtle.importKey(
    "raw",
    bobKeyPair.publicKey,
    { name: "X25519" },
    true,
    []
  );

  const aliceSharedBits = await subtle.deriveBits(
    { name: "X25519", public: subtleImportBobPub },
    aliceKeyPair.privateKey,
    256
  );
  const aliceShared = new Uint8Array(aliceSharedBits);
  const bobShared = sharedKey(
    bobKeyPair.secretKey,
    new Uint8Array(rawAlicePublicKey)
  );

  assert(
    eq(aliceShared, bobShared),
    `X25519 derived shared secrets do not match SubtleCrypto`
  );
}

const testVectors = [
  // Test vectors from RFC 7748 §5.2
  {
    scalar: "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
    u: "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
    expected:
      "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
  },
  {
    scalar: "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
    u: "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
    expected:
      "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957",
  },
  // small order point
  {
    scalar: "0900000000000000000000000000000000000000000000000000000000000000",
    u: "0000000000000000000000000000000000000000000000000000000000000000",
    expected:
      "0000000000000000000000000000000000000000000000000000000000000000",
  },
  // RFC 7748 §6.1 Alice private key
  {
    scalar: "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
    u: "0900000000000000000000000000000000000000000000000000000000000000",
    expected:
      "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
  },
  // RFC 7748 §6.1 Bobs private, alice's public -> shared secret
  {
    scalar: "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
    u: "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
    expected:
      "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
  },
  // RFC 7748 §6.1 Alice's private key, Bobs public -> shared secret
  {
    scalar: "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
    u: "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
    expected:
      "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
  },
  // wrong size u
  {
    scalar: "1234000000000000000000000000000000000000000000000000000000000000",
    u: "00000000000000000000000000000000000000000000000000000000000000",
    expected:
      "0000000000000000000000000000000000000000000000000000000000000000",
    expectThrows: true,
  },
  // wrong size scalar
  {
    scalar: "12340000000000000000000000000000000000000000000000000000000000",
    u: "0000000000000000000000000000000000000000000000000000000000000000",
    expected:
      "0000000000000000000000000000000000000000000000000000000000000000",
    expectThrows: true,
  },
];

const x25519Cases = testVectors.map((tv, i) => ({
  name: `RFC 7748 Vector ${i + 1}`,
  vector: tv,
  expectThrows: tv.expectThrows || false,
}));

async function runOneX25519OnTestVectors(tc) {
  const tv = tc.vector;
  const scalarU8 = u8(tv.scalar);
  const uU8 = u8(tv.u);
  let outU8;
  try {
    outU8 = x25519(scalarU8, uU8);
  } catch (e) {
    if (tc.expectThrows) return;
    throw e;
  }
  const outHex = hex(outU8);
  if (outHex !== tv.expected) {
    throw new Error(
      `[${tc.name}] X25519 output mismatch\nexpected: ${tv.expected}\n got:    ${outHex}`
    );
  }
}

const smallOrderList = [
  "0000000000000000000000000000000000000000000000000000000000000000",
  "0100000000000000000000000000000000000000000000000000000000000000",
  "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
  "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
];

const smallOrderCases = smallOrderList.map((hexStr, i) => ({
  name: `Small Order Test ${i + 1}`,
  hexStr,
}));

async function runOneX25519OnSmallOrder(tc) {
  const pkRaw = u8(tc.hexStr);
  const aliceKeyPair = generateKeyPair();
  let derived;
  try {
    derived = sharedKey(aliceKeyPair.secretKey, pkRaw);
  } catch {
    return;
  }
  throw new Error(
    `[${
      tc.name
    }] Expected error when using small order public key, but got derived key: ${hex(
      derived
    )}`
  );
}

// ---------- runner -----------

const tests = [
  { name: "AES-256-GCM", cases: aes256gcmcases, runner: runOneaes256gcm },
  { name: "SHA-256", cases: sha256Cases, runner: runOneSha256 },
  { name: "HMAC-SHA256", cases: hmacSha256Cases, runner: runOneHmacSha256 },
  { name: "PBKDF2-HMAC-SHA256", cases: pbkdf2Cases, runner: runOnePbkdf2 },
  {
    name: "PBKDF2 + AES-256-GCM Integration",
    cases: pbkdfAESCases,
    runner: runOnePbkdfAes,
  },
  {
    name: "X25519 Key Agreement",
    cases: [{ name: "basic" }, { name: "basic2" }],
    runner: runOneX25519GetSameKey,
  },
  {
    name: "X25519 vs SubtleCrypto",
    cases: [{ name: "subtle match" }, { name: "subtle match2" }],
    runner: runOneX25519MatchesSubtle,
  },
  {
    name: "X25519 Test Vectors",
    cases: x25519Cases,
    runner: runOneX25519OnTestVectors,
  },
  {
    name: "X25519 Small Order Public Keys",
    cases: smallOrderCases,
    runner: runOneX25519OnSmallOrder,
  },
];

async function runAll() {
  let totalFailed = 0;
  for (const testGroup of tests) {
    console.log(`\n=== ${testGroup.name} tests ===`);
    let failed = 0;
    for (const tc of testGroup.cases) {
      try {
        await testGroup.runner(tc);
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
