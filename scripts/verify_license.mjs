#!/usr/bin/env node
// Verifies scripts/license.json the same way both product processes do,
// using the (swapped) public key committed in the repo:
//
//   Node backend  — backend/src/lib/crypto/signing.ts:
//     createPublicKey({type:"pkcs1"}) + createVerify("SHA256") over
//     JSON.stringify(parsedLicense)
//   Go sidecar    — backend-go/.../license.go:
//     x509.ParsePKCS1PublicKey + rsa.VerifyPKCS1v15(sha256(rawLicenseBytes))
//
// Exits non-zero on any failure. Usage: node scripts/verify_license.mjs
//   (optionally: node scripts/verify_license.mjs <licenseKeyBase64> to verify
//    an already-base64'd key, e.g. the one from deploy/.env)

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));

let contentsJSON;
const arg = process.argv[2];
if (arg) {
  contentsJSON = Buffer.from(arg, "base64").toString("utf8");
} else {
  contentsJSON = fs.readFileSync(path.join(here, "license.json"), "utf8");
}

const contents = JSON.parse(contentsJSON);
if (typeof contents.signature !== "string" || !contents.signature) {
  throw new Error("missing signature");
}
const license = contents.license;

const nodeKey = fs.readFileSync(
  path.join(here, "../backend/src/lib/crypto/license_public_key.pem"),
  "utf8"
);
const goKey = fs.readFileSync(
  path.join(here, "../backend-go/internal/ee/services/license/keys/license_public_key.pem"),
  "utf8"
);

const check = (name, data, pem, type) => {
  // Mirrors Node signing.ts / Go verifyOfflineLicenseSignature (PKCS1v1.5 SHA256)
  const key = crypto.createPublicKey({ key: pem, format: "pem", type });
  const ok = crypto
    .createVerify("SHA256")
    .update(data)
    .verify(key, Buffer.from(contents.signature, "base64"));
  if (!ok) throw new Error(`${name}: signature verification FAILED`);
  console.log(`${name}: signature OK`);
};

// Node path: re-serialized parsed object
check("node  (re-serialized)", JSON.stringify(license), nodeKey, "pkcs1");
// Go path: raw bytes exactly as stored in the file
const licenseMarker = '{"license":';
const rawLicenseBytes = contentsJSON.slice(
  contentsJSON.indexOf(licenseMarker) + licenseMarker.length,
  contentsJSON.indexOf(',"signature"')
);
check("go    (raw bytes)", rawLicenseBytes, goKey, "pkcs1");

if (nodeKey !== goKey) throw new Error("node and go public keys differ");
console.log("keys: node == go public key");

// terminatesAt (the only enforced expiry, both processes)
if (license.terminatesAt) {
  const t = new Date(license.terminatesAt);
  if (t < new Date()) throw new Error(`license terminated at ${t.toISOString()}`);
  console.log(`terminatesAt: ${t.toISOString()} (valid)`);
} else {
  console.log("terminatesAt: null (no termination date)");
}

// Enterprise assertions (silent-OSS-mode guard: assert TYPE, not presence)
const f = license.features;
const assert = (cond, what) => {
  if (!cond) throw new Error(`feature check failed: ${what}`);
};
assert(f.slug === "enterprise", `slug=${f.slug}`);
assert(f.samlSSO && f.oidcSSO && f.ldap && f.scim, "SSO features");
assert(f.rbac && f.groups, "RBAC/groups");
assert(f.auditLogs && f.auditLogStreams, "audit logs");
assert(f.hsm && f.externalKms && f.kmsPqc, "KMS features");
assert(f.pkiAcme && f.caCrl && f.pkiScep && f.pkiDiscovery, "PKI features");
assert(f.gateway && f.gatewayPool, "gateways");
assert(f.memberLimit === null && f.identityLimit === null, "seat limits unlimited");
assert(f.enforceIdentityLimit === false, "identity limit bypass");
assert(f.fips === true, "fips capability");
console.log(`features: enterprise (${Object.keys(f).length} fields) — all assertions pass`);
console.log("VERIFY: PASS");
