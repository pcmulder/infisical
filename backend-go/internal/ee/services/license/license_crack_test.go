package license

// Rebase guard: the committed self-hosted license (scripts/license.json)
// must keep verifying against the embedded public key after any upstream
// change. Run: go test ./internal/ee/services/license/ -run TestCrackEnterpriseLicense

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCrackEnterpriseLicense(t *testing.T) {
	raw, err := os.ReadFile("../../../../../scripts/license.json")
	require.NoError(t, err)

	var contents struct {
		License   json.RawMessage `json:"license"`
		Signature string          `json:"signature"`
	}
	require.NoError(t, json.Unmarshal(raw, &contents))

	// Same check the Go sidecar performs at boot.
	require.NoError(t, verifyOfflineLicenseSignature(contents.License, contents.Signature),
		"committed license must verify against the embedded public key")

	// Expiry (the only enforced date).
	var lic struct {
		TerminatesAt *string `json:"terminatesAt"`
		Features     struct {
			Slug     string `json:"slug"`
			RBAC     bool   `json:"rbac"`
			SamlSSO  bool   `json:"samlSSO"`
			AuditLog bool   `json:"auditLogs"`
		} `json:"features"`
	}
	require.NoError(t, json.Unmarshal(contents.License, &lic))

	if lic.TerminatesAt != nil {
		term, err := time.Parse(time.RFC3339, *lic.TerminatesAt)
		require.NoError(t, err)
		require.False(t, time.Now().After(term), "license terminated at %s", term)
	}

	require.Equal(t, "enterprise", lic.Features.Slug)
	require.True(t, lic.Features.RBAC)
	require.True(t, lic.Features.SamlSSO)
	require.True(t, lic.Features.AuditLog)
}
