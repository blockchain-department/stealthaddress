// receiver_reconstruct.js
const fs = require("fs");
const path = require("path");
const BN = require("bn.js");
const EC = require("elliptic").ec;
const keccak256 = require("keccak256");
const ec = new EC("secp256k1");

function strip0x(s) { return s.replace(/^0x/, ""); }
function to0x(s) { return s.startsWith("0x") ? s : "0x" + s; }
function keccakHex(buf) { return keccak256(buf).toString("hex"); }

function computeAddressFromUncompressedHex(uncompNo0x) {
  const pubBytes = Buffer.from(uncompNo0x, "hex").slice(1); // X||Y
  const addrHex = keccak256(pubBytes).toString("hex").slice(-40);
  return "0x" + addrHex;
}

function loadJSON(p) {
  if (!fs.existsSync(p)) throw new Error(`${p} not found`);
  return JSON.parse(fs.readFileSync(p, "utf8"));
}

function bytesToBigInt(bytes) {
  return BigInt("0x" + Buffer.from(bytes).toString("hex"));
}

function bnToHex(bn, len = 64) {
  return bn.toString(16).padStart(len, "0");
}

function main() {
  const receiver = loadJSON(path.join(process.cwd(), "keys", "receiver.json"));
  const ann = loadJSON(path.join(process.cwd(), "keys", "announcement.json"));

  // extract ephemeral pub (uncompressed) from announcement
  const ephPubUncomp0x = ann.ephemeralPubUncompressed;
  if (!ephPubUncomp0x) {
    console.error("announcement.json missing ephemeralPubUncompressed");
    process.exit(1);
  }
  const ephPubUncompNo0x = strip0x(ephPubUncomp0x);

  // compute shared X = scanPriv * ephPub
  const scanPrivHex = strip0x(receiver.scan.privateKey);
  const scanKey = ec.keyFromPrivate(scanPrivHex, "hex");
  const ephPubPoint = ec.keyFromPublic(ephPubUncompNo0x, "hex").getPublic();
  const sharedX_bn = scanKey.derive(ephPubPoint); // BN
  const sharedXBuf = Buffer.from(sharedX_bn.toArray("be", 32));

  // tweak = keccak256(sharedXBuf) % n
  const sharedHashHex = keccakHex(sharedXBuf);
  const tweak_bn = new BN(sharedHashHex, 16).umod(ec.curve.n);
  const tweakNonZero = tweak_bn.isZero() ? new BN(1) : tweak_bn;

  // stealthPriv = spendPriv + tweak mod n
  const spendPrivBN = new BN(strip0x(receiver.spend.privateKey), 16);
  const stealthPrivBN = spendPrivBN.add(tweakNonZero).umod(ec.curve.n);
  const stealthPrivHex = bnToHex(stealthPrivBN, 64);
  const stealthPriv0x = to0x(stealthPrivHex);

  // stealth pub & address
  const stealthKey = ec.keyFromPrivate(stealthPrivHex, "hex");
  const stealthPubUncomp = stealthKey.getPublic().encode("hex", false);
  const stealthAddress = computeAddressFromUncompressedHex(stealthPubUncomp);

  // debug prints
  console.log("🔑 sharedX (hex): 0x" + sharedXBuf.toString("hex"));
  console.log("🧪 sharedHash (keccak(sharedX)):", "0x" + sharedHashHex);
  console.log("🧩 tweak (hex): 0x" + bnToHex(tweakNonZero, 64));
  console.log("🔐 stealthPriv (0x):", stealthPriv0x);
  console.log("📬 stealthPub (uncompressed 0x):", to0x(stealthPubUncomp));
  console.log("📥 stealthAddress:", stealthAddress);

  if (ann.stealthAddress) {
    if (ann.stealthAddress.toLowerCase() === stealthAddress.toLowerCase()) {
      console.log("✅ MATCH: receiver derived the same stealth address as sender");
    } else {
      console.warn("❌ MISMATCH: derived address differs from sender");
      console.log("sender:", ann.stealthAddress);
    }
  } else {
    console.log("ℹ️ announcement.json did not include stealthAddress to compare.");
  }
}

main();
