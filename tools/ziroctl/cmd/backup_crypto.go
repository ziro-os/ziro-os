package cmd

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Encrypted backups. An archive that carries secrets (cluster keys, the Raft log, API tokens) is
// sealed with AES-256-GCM in chunks, so a stolen backup, or one uploaded to an object store, is
// useless without the host's backup key. The key lives in backupKeyPath, is never part of any
// archive, and must be copied somewhere safe by the operator (`ziroctl backup key show`): without
// it an encrypted backup cannot be opened, here or anywhere else.
//
// Format: "ZIROBK1\n", an 8-byte random nonce prefix, then chunks of [4-byte length][sealed data].
// A chunk's nonce is the prefix plus a 4-byte counter. Its additional data is 1 for the last
// chunk and 0 otherwise, so cutting the stream short fails authentication instead of looking
// like a smaller archive.

var backupKeyPath = "/etc/ziro/backup.key"

const (
	backupMagic     = "ZIROBK1\n"
	backupChunkSize = 64 << 10
	backupMaxChunk  = backupChunkSize + 16
)

// loadBackupKey reads the key at path, creating it first when create is set and it is missing.
func loadBackupKey(path string, create bool) (key []byte, created bool, err error) {
	if b, err := os.ReadFile(path); err == nil {
		key, err = hex.DecodeString(strings.TrimSpace(string(b)))
		if err != nil || len(key) != 32 {
			return nil, false, fmt.Errorf("%s is not a backup key (want 64 hex characters)", path)
		}
		return key, false, nil
	} else if !os.IsNotExist(err) || !create {
		if os.IsNotExist(err) {
			err = fmt.Errorf("no backup key at %s (the host that made the backup has it; `ziroctl backup key show` prints it)", path)
		}
		return nil, false, err
	}
	key = make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, false, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, false, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, false, err
	}
	_, werr := f.WriteString(hex.EncodeToString(key) + "\n")
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		os.Remove(path)
		return nil, false, werr
	}
	return key, true, nil
}

func newBackupGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func chunkNonce(prefix []byte, n uint32) []byte {
	nonce := make([]byte, 12)
	copy(nonce, prefix)
	binary.BigEndian.PutUint32(nonce[8:], n)
	return nonce
}

// encryptWriter seals what is written to it into w. Close writes the last chunk and must be called.
type encryptWriter struct {
	w      io.Writer
	aead   cipher.AEAD
	prefix []byte
	n      uint32
	buf    []byte
}

func newEncryptWriter(w io.Writer, key []byte) (*encryptWriter, error) {
	aead, err := newBackupGCM(key)
	if err != nil {
		return nil, err
	}
	prefix := make([]byte, 8)
	if _, err := rand.Read(prefix); err != nil {
		return nil, err
	}
	if _, err := w.Write(append([]byte(backupMagic), prefix...)); err != nil {
		return nil, err
	}
	return &encryptWriter{w: w, aead: aead, prefix: prefix}, nil
}

func (e *encryptWriter) seal(final bool) error {
	ad := []byte{0}
	if final {
		ad[0] = 1
	}
	sealed := e.aead.Seal(nil, chunkNonce(e.prefix, e.n), e.buf, ad)
	e.n++
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(sealed)))
	e.buf = e.buf[:0]
	_, err := e.w.Write(append(hdr[:], sealed...))
	return err
}

func (e *encryptWriter) Write(p []byte) (int, error) {
	written := len(p)
	for len(p) > 0 {
		n := min(len(p), backupChunkSize-len(e.buf))
		e.buf = append(e.buf, p[:n]...)
		p = p[n:]
		// A full buffer is sealed only when more data follows, so the last chunk is always the final one.
		if len(e.buf) == backupChunkSize && len(p) > 0 {
			if err := e.seal(false); err != nil {
				return 0, err
			}
		}
	}
	return written, nil
}

func (e *encryptWriter) Close() error { return e.seal(true) }

// decryptReader opens a stream written by encryptWriter.
type decryptReader struct {
	r      io.Reader
	aead   cipher.AEAD
	prefix []byte
	n      uint32
	plain  []byte
	next   []byte // the following chunk's sealed bytes, read ahead to know whether this one is last
	done   bool
}

var errBackupAuth = errors.New("backup is damaged, truncated, or the key is wrong")

func newDecryptReader(r io.Reader, key []byte) (*decryptReader, error) {
	aead, err := newBackupGCM(key)
	if err != nil {
		return nil, err
	}
	head := make([]byte, len(backupMagic)+8)
	if _, err := io.ReadFull(r, head); err != nil || string(head[:len(backupMagic)]) != backupMagic {
		return nil, errors.New("not an encrypted Ziro backup")
	}
	d := &decryptReader{r: r, aead: aead, prefix: head[len(backupMagic):]}
	if d.next, err = d.readChunk(); err != nil {
		return nil, err
	}
	return d, nil
}

// readChunk returns the next sealed chunk, or nil at the clean end of the stream.
func (d *decryptReader) readChunk() ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(d.r, hdr[:]); err == io.EOF {
		return nil, nil
	} else if err != nil {
		return nil, errBackupAuth
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n < 16 || n > backupMaxChunk {
		return nil, errBackupAuth
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(d.r, buf); err != nil {
		return nil, errBackupAuth
	}
	return buf, nil
}

func (d *decryptReader) Read(p []byte) (int, error) {
	for len(d.plain) == 0 {
		if d.done {
			return 0, io.EOF
		}
		if d.next == nil {
			return 0, errBackupAuth // the stream ended without a final chunk
		}
		cur := d.next
		var err error
		if d.next, err = d.readChunk(); err != nil {
			return 0, err
		}
		final := d.next == nil
		ad := []byte{0}
		if final {
			ad[0] = 1
		}
		if d.plain, err = d.aead.Open(nil, chunkNonce(d.prefix, d.n), cur, ad); err != nil {
			return 0, errBackupAuth
		}
		d.n++
		d.done = final
	}
	n := copy(p, d.plain)
	d.plain = d.plain[n:]
	return n, nil
}
