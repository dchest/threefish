package threefish

import (
	"bytes"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	in := make([]byte, BlockSize)
	for i := range in {
		in[i] = byte(i)
	}
	out := make([]byte, BlockSize)
	k := make([]byte, KeySize)
	tw := make([]byte, TweakSize)
	for i := range tw {
		tw[i] = byte(i)
	}
	c, err := NewCipher(k, tw)
	if err != nil {
		t.Errorf("%s", err)
	}
	c.Encrypt(out, in)
	if bytes.Equal(out, in) {
		t.Errorf("ciphertext is the same as plaintext")
	}
	c.Decrypt(out, out)
	if !bytes.Equal(out, in) {
		t.Errorf("encryption/decryption failed")
	}
}