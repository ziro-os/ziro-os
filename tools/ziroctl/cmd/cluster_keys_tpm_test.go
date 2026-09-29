//go:build tpmsim

// The TPM simulator is C (cgo) and needs the OpenSSL headers, so this test only builds with
// -tags tpmsim (CI runs it separately with libssl-dev installed).
package cmd

import (
	"bytes"
	"testing"

	"github.com/google/go-tpm/tpm2/transport/simulator"
)

func TestTPMSeal(t *testing.T) {
	tpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Skipf("TPM simulator: %v", err)
	}
	key := newDEK()
	blob, err := tpmSeal(tpm, key)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(blob, key) {
		t.Fatal("sealed blob contains the key")
	}
	got, err := tpmUnseal(tpm, blob)
	if err != nil || !bytes.Equal(got, key) {
		t.Fatalf("unseal: %v", err)
	}
	tpm.Close()

	// Another TPM (a fresh simulator has a different seed) cannot unseal it.
	other, err := simulator.OpenSimulator()
	if err != nil {
		t.Skip(err)
	}
	defer other.Close()
	if _, err := tpmUnseal(other, blob); err == nil {
		t.Fatal("a different TPM unsealed the key")
	}
}
