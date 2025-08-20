// generateReceiverKeys.js
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const EC = require("elliptic").ec;
const keccak256 = require("keccak256");
const ec = new EC("secp256k1");
const BN = require("bn.js");

function to0x(hex) { return hex.startsWith("0x") ? hex : "0x" + hex; }
function strip0x(s) { return s.replace(/^0x/, ""); }

// EIP-55 checksum
function toChecksumAddress(address) {
  const addr = strip0x(address).toLowerCase();
  const hash = keccak256(Buffer.from(addr, "ascii")).toString("hex");
  let out = "0x";
  for (let i = 0; i < addr.length; i++) {
    const c = addr[i];
    const h = parseInt(hash[i], 16);
    out += (h >= 8) ? c.toUpperCase() : c;
  }
  return out;
}

function pubToAddress(uncompressedHexNo0x) {
  // uncompressedHexNo0x should start with '04'
  const pubBytes = Buffer.from(uncompressedHexNo0x, "hex").slice(1); // X||Y
  const hash = keccak256(pubBytes).toString("hex");
  const address = "0x" + hash.slice(-40);
  return toChecksumAddress(address);
}

function genKeyHex() {
  const priv = crypto.randomBytes(32).toString("hex");
  const key = ec.keyFromPrivate(priv, "hex");
  const pubPoint = key.getPublic();
  const pubUncompressed = pubPoint.encode("hex", false); // '04' + X + Y
  const pubCompressed = pubPoint.encode("hex", true);     // '02'/'03' + X
  const pubX = pubPoint.getX().toString("hex", 64);

  return {
    privateKey: to0x(priv),
    publicKeyUncompressed: to0x(pubUncompressed),
    publicKeyCompressed: to0x(pubCompressed),
    publicKeyX: to0x(pubX)
  };
}

function main() {
  const scan = genKeyHex();
  const spend = genKeyHex();

  const baseEthAddress = pubToAddress(strip0x(spend.publicKeyUncompressed));

  const out = {
    scan,
    spend,
    baseEthAddress
  };

  const keysDir = path.join(process.cwd(), "keys");
  if (!fs.existsSync(keysDir)) fs.mkdirSync(keysDir, { recursive: true });
  fs.writeFileSync(path.join(keysDir, "receiver.json"), JSON.stringify(out, null, 2), "utf8");

  console.log("✅ Saved receiver keys -> ./keys/receiver.json");
  console.log({ scanPubX: scan.publicKeyX, spendPubX: spend.publicKeyX, baseEthAddress });
}

main();
