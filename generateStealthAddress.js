// sender_createStealth.js
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const EC = require("elliptic").ec;
const keccak256 = require("keccak256");
const BN = require("bn.js");
const ec = new EC("secp256k1");

function to0x(h) { return h.startsWith("0x") ? h : "0x" + h; }
function strip0x(s) { return s.replace(/^0x/, ""); }
function keccakHex(buf) { return keccak256(buf).toString("hex"); }

function computeAddressFromUncompressedHex(uncompNo0x) {
  const pubBytes = Buffer.from(uncompNo0x, "hex").slice(1); // X||Y
  const addrHex = keccak256(pubBytes).toString("hex").slice(-40);
  // simple non-checksummed address returned; correct checksum optional
  return "0x" + addrHex;
}

function main() {
  const recPath = path.join(process.cwd(), "keys", "receiver.json");
  if (!fs.existsSync(recPath)) {
    console.error("Missing keys/receiver.json (run generateReceiverKeys.js first)");
    process.exit(1);
  }
  const receiver = JSON.parse(fs.readFileSync(recPath, "utf8"));

  // ephemeral key
  const ephPrivHex = crypto.randomBytes(32).toString("hex");
  const ephKey = ec.keyFromPrivate(ephPrivHex, "hex");
  const ephPubPoint = ephKey.getPublic();
  const ephPubUncomp = ephPubPoint.encode("hex", false); // no 0x
  const ephPubUncomp0x = to0x(ephPubUncomp);

  // compute shared X: ECDH (ephemeralPriv * scanPub)
  const scanPubUncompNo0x = strip0x(receiver.scan.publicKeyUncompressed);
  const scanPubPoint = ec.keyFromPublic(scanPubUncompNo0x, "hex").getPublic();
  const sharedX_bn = ephKey.derive(scanPubPoint); // BN (x coordinate)
  const sharedXBuf = Buffer.from(sharedX_bn.toArray("be", 32)); // 32 bytes

  // tweak = keccak256(sharedXBuf) mod n
  const sharedHashHex = keccakHex(sharedXBuf);
  const tweak_bn = new BN(sharedHashHex, 16).umod(ec.curve.n);
  const tweakNonZero = tweak_bn.isZero() ? new BN(1) : tweak_bn;

  // stealth pub = spendPub + tweak*G
  const spendPubUncompNo0x = strip0x(receiver.spend.publicKeyUncompressed);
  const spendPoint = ec.keyFromPublic(spendPubUncompNo0x, "hex").getPublic();
  const tweakPoint = ec.g.mul(tweakNonZero);
  const stealthPoint = spendPoint.add(tweakPoint);
  const stealthPubUncomp = stealthPoint.encode("hex", false);
  const stealthPubUncomp0x = to0x(stealthPubUncomp);

  // stealth private = spendPriv + tweak mod n
  const spendPrivBN = new BN(strip0x(receiver.spend.privateKey), 16);
  const stealthPrivBN = spendPrivBN.add(tweakNonZero).umod(ec.curve.n);
  const stealthPrivHex = stealthPrivBN.toString(16).padStart(64, "0");
  const stealthPriv0x = to0x(stealthPrivHex);

  // stealth address (non-checksummed)
  const stealthAddress = computeAddressFromUncompressedHex(stealthPubUncomp);

  // ephemeral pub hash (contract bytes32)
  const ephPubHash = "0x" + keccakHex(Buffer.from(ephPubUncomp, "hex"));

  // Build encryptedPayload = ephemeralPubUncompressed || ciphertext (dummy)
  const dummyCipher = Buffer.from("hello receiver", "utf8");
  const encryptedPayload = Buffer.concat([Buffer.from(ephPubUncomp, "hex"), dummyCipher]);
  const encryptedPayloadHex = "0x" + encryptedPayload.toString("hex");

  const announcement = {
    ephemeralPrivKey: to0x(ephPrivHex),
    ephemeralPubUncompressed: ephPubUncomp0x,
    ephemeralPubHash: ephPubHash,
    encryptedPayload: encryptedPayloadHex,
    stealthPriv: stealthPriv0x,
    stealthPubUncompressed: stealthPubUncomp0x,
    stealthAddress
  };

  fs.writeFileSync(path.join(process.cwd(), "keys", "announcement.json"), JSON.stringify(announcement, null, 2), "utf8");

  console.log("✅ Announcement written -> ./keys/announcement.json");
  console.log({ ephemeralPubHash, encryptedPayload: encryptedPayloadHex, stealthAddress });
}

main();
