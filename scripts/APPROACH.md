# Self-hosted enterprise license — approach

Offline (air-gapped) enterprise licenses are verified locally against the
public key embedded in both license-aware processes:

- Node backend: `backend/src/lib/crypto/license_public_key.pem`
  (read at runtime; in the image: `/backend/dist/lib/crypto/...`)
- Go sidecar: `//go:embed` of
  `backend-go/internal/ee/services/license/keys/license_public_key.pem`

Signature scheme: RSA-2048 PKCS#1 key, SHA-256, PKCS1v1.5, over the exact
JSON bytes of the `license` object (compact ASCII; the Node path
re-serializes with `JSON.stringify`, which is byte-identical).

License format (env `LICENSE_KEY`): `base64(JSON.stringify({license,
signature}))` where `license` is the offline license document
(`issuedTo`, `licenseId`, `issuedAt`, `terminatesAt` (the only enforced
expiry), `version: 1`, `features` — a full feature set; the Go loader
unmarshals into a zero-valued struct, so the set must be complete).

Artifacts:

- `scripts/.signing_key.pem` — private key. Gitignored, 0600, not committed.
  Backed up in the password manager. Re-minting is a one-minute job, so the
  license carries a one-year `terminatesAt` (re-mint annually).
- `scripts/license.json` — the current license document (`{license,
  signature}`). Not a secret: the public key is public in the image.
- `scripts/mint_license.mjs` — builds the license from the private key,
  signs, writes `license.json`, prints `LICENSE_KEY`.
- `scripts/verify_license.mjs` — verifies `license.json` (or a key passed as
  argv[1]) the way both processes do; asserts the enterprise feature set.
- `Dockerfile.enterprise` — thin image on the official standalone image:
  swaps the Node key file and rebuilds the Go sidecar with the swapped
  embedded key. `CGO_ENABLED=1` (the sidecar links PKCS#11 libraries).
- `backend-go/internal/ee/services/license/license_crack_test.go` —
  rebase guard: the committed license must keep verifying against the
  embedded key. Run: `go test ./internal/ee/services/license/ -run
  TestCrackEnterpriseLicense` (Go >= 1.26).

Deployment: set `LICENSE_KEY` in the environment; `TELEMETRY_ENABLED=false`
disables telemetry; no other phone-home on the offline path.
