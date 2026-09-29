package cmd

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"os"
	"testing"

	"github.com/google/go-tpm/tpm2"
)

// rawTPM sends TPM 2.0 commands over swtpm's data socket: raw command bytes out, and the
// response framed by the size in its 10-byte header.
type rawTPM struct{ c net.Conn }

func (r rawTPM) Send(cmd []byte) ([]byte, error) {
	if _, err := r.c.Write(cmd); err != nil {
		return nil, err
	}
	hdr := make([]byte, 10)
	if _, err := io.ReadFull(r.c, hdr); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[2:6])
	if n < 10 || n > 1<<16 {
		return nil, io.ErrUnexpectedEOF
	}
	rsp := make([]byte, n)
	copy(rsp, hdr)
	_, err := io.ReadFull(r.c, rsp[10:])
	return rsp, err
}

// TestTPMSeal runs the TPM provider against swtpm, a software TPM 2.0 (the libtpms engine used by
// QEMU and libvirt vTPMs). It is skipped unless ZIRO_TPM_SIM names swtpm's data socket. CI starts:
//
//	swtpm socket --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 \
//	  --tpmstate dir=$(mktemp -d) --flags not-need-init,startup-clear &
//	ZIRO_TPM_SIM=127.0.0.1:2321 go test -run TestTPMSeal ./cmd
func TestTPMSeal(t *testing.T) {
	addr := os.Getenv("ZIRO_TPM_SIM")
	if addr == "" {
		t.Skip("set ZIRO_TPM_SIM=host:port of a swtpm data socket to run")
	}
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	tpm := rawTPM{conn}

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

	// TPM2_Clear regenerates the owner seed, as a TPM reset or a change of owner does: the old
	// SRK, and with it the sealed key, is gone for good.
	if _, err := (tpm2.Clear{AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHLockout, Auth: tpm2.PasswordAuth(nil)}}).Execute(tpm); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if _, err := tpmUnseal(tpm, blob); err == nil {
		t.Fatal("unsealed after the owner seed changed")
	}
}
