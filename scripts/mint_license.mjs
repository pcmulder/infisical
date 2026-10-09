#!/usr/bin/env node
// Mints an Infisical self-hosted OFFLINE (air-gapped) enterprise license.
//
// Output:
//   scripts/license.json   — exact bytes {license, signature} (no trailing newline)
//   stdout                 — LICENSE_KEY: base64(license.json), for deploy/.env
//
// Signing target: the exact JSON bytes of the `license` object (compact, ASCII),
// RSA-PKCS1v1.5 / SHA-256. Node re-serializes the parsed license with
// JSON.stringify (key order preserved) before verifying, so both the Node
// backend and the Go sidecar (raw bytes) verify against the same bytes.
//
// The features object mirrors TFeatureSet
// (backend/src/ee/services/license/license-types.ts) field-for-field; the Go
// loader unmarshals into a zero-valued FeatureSet, so every field it consumes
// must be present here. A type test in backend/ (license-crack) guards against
// drift when TFeatureSet changes upstream.
//
// Re-mint (annual): LICENSE_ISSUED_AT / LICENSE_TERMINATES_AT env overrides.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const PRIVATE_KEY = fs.readFileSync(path.join(here, ".signing_key.pem"));

const oneYearMs = 365 * 24 * 60 * 60 * 1000;
const issuedAt = new Date(process.env.LICENSE_ISSUED_AT || Date.now());
const terminatesAt = new Date(
  process.env.LICENSE_TERMINATES_AT || issuedAt.getTime() + oneYearMs
);

// Full enterprise feature set (all capabilities on, all limits null = unlimited).
const features = {
  _id: null,
  slug: "enterprise",
  tier: -1,
  workspaceLimit: null,
  workspacesUsed: 0,
  dynamicSecret: true,
  memberLimit: null,
  identityLimit: null,
  enforceIdentityLimit: false,
  subOrganization: true,
  environmentLimit: null,
  environmentsUsed: 0,
  secretVersioning: true,
  pitRecovery: true,
  ipAllowlisting: true,
  rbac: true,
  customRateLimits: true,
  customAlerts: true,
  auditLogs: true,
  auditLogsRetentionDays: 36500,
  auditLogStreams: true,
  auditLogStreamLimit: 1000,
  githubOrgSync: true,
  samlSSO: true,
  enforceGoogleSSO: true,
  hsm: true,
  oidcSSO: true,
  secretAccessInsights: true,
  scim: true,
  ldap: true,
  groups: true,
  status: null,
  trial_end: null,
  has_used_trial: true,
  secretApproval: true,
  secretRotation: true,
  instanceUserManagement: true,
  externalKms: true,
  rateLimits: {
    readLimit: 10000,
    writeLimit: 10000,
    secretsLimit: 100000
  },
  kmsPqc: true,
  enforceMfa: true,
  projectTemplates: true,
  kmip: true,
  gateway: true,
  gatewayPool: true,
  pamSlackNotifications: true,
  secretScanning: true,
  enterpriseSecretSyncs: true,
  enterpriseAppConnections: true,
  machineIdentityAuthTemplates: true,
  fips: true,
  eventSubscriptions: true,
  secretShareExternalBranding: true,
  honeyTokens: true,
  honeyTokenLimit: 10000,
  secretsBrokering: true,
  agentVaultByoS3: true,
  secretSyncLimit: null,
  maxPamAccounts: null,
  // PKI / Cert Manager
  pkiAcme: true,
  pkiEst: true,
  pkiScep: true,
  pkiPqc: true,
  caCrl: true,
  pkiOcsp: true,
  pkiEnterpriseCaIntegrations: true,
  pkiExternalIntermediateCa: true,
  pkiDiscovery: true,
  pkiEnterpriseAlerting: true,
  pkiApprovals: true,
  pkiSyncs: true,
  pkiLegacyTemplates: true,
  pkiCodeSigning: true,
  maxCas: null,
  maxInternalCas: null,
  maxCertificates: null,
  maxWildcardCertificates: null,
  maxSansPerCertificate: null,
  // product gating
  pam: null,
  certManager: null,
  secretsTemporaryAccess: null,
  enterprisePamAccount: null,
  crossProjectSecretSharing: true,
  secretsFolderRbac: true
};

const license = {
  issuedTo: process.env.LICENSE_ISSUED_TO || "Weaver for Travel",
  licenseId: process.env.LICENSE_ID || "selfhosted-enterprise-2026-0001",
  customerId: null,
  issuedAt: issuedAt.toISOString(),
  expiresAt: null,
  terminatesAt: terminatesAt.toISOString(),
  version: 1,
  features
};

const licenseJSON = JSON.stringify(license);
const signature = crypto
  .createSign("sha256")
  .update(licenseJSON)
  .sign(PRIVATE_KEY)
  .toString("base64");

const contentsJSON = JSON.stringify({ license, signature });
const licenseKey = Buffer.from(contentsJSON, "utf8").toString("base64");

fs.writeFileSync(path.join(here, "license.json"), contentsJSON);

console.log(
  `issuedAt=${issuedAt.toISOString()} terminatesAt=${terminatesAt.toISOString()} licenseJsonBytes=${licenseJSON.length}`
);
console.log(`LICENSE_KEY=${licenseKey}`);
