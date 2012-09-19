// Copyright 2012 Dmitry Chestnykh. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package threefish

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func fromHex(s string) []byte {
	ret, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return ret
}

var testVectors = []struct {
	k   []byte
	t   []byte
	in  []byte
	out []byte
}{
	{
		make([]byte, KeySize),
		make([]byte, TweakSize),
		make([]byte, BlockSize),
		fromHex("b1a2bbc6ef6025bc40eb3822161f36e375d1bb0aee3186fbd19e47c5d479947b7bc2f8586e35f0cff7e7f03084b0b7b1f1ab3961a580a3e97eb41ea14a6d7bbe"),
	},
}

func TestEncrypt(t *testing.T) {
	out := make([]byte, BlockSize)
	for i, v := range testVectors {
		c, err := NewCipher(v.k, v.t)
		if err != nil {
			t.Errorf("%s", err)
		}
		c.Encrypt(out, v.in)
		if !bytes.Equal(v.out, out) {
			t.Errorf("%d: expected %x, got %x", i, v.out, out)
		}
	}
}

func TestEncryptDecrypt(t *testing.T) {
	in := make([]byte, BlockSize)
	for i := range in {
		in[i] = byte(i)
	}
	out := make([]byte, BlockSize)
	k := make([]byte, KeySize)
	for i := range k {
		k[i] = byte(i * 2)
	}
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

func BenchmarkEncrypt(b *testing.B) {
	v := testVectors[0]
	c, err := NewCipher(v.k, v.t)
	if err != nil {
		b.Fatal("NewCipher: ", err)
	}
	out := make([]byte, len(v.out))
	b.SetBytes(int64(len(out)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Encrypt(out, v.in)
	}
}

func BenchmarkDecrypt(b *testing.B) {
	v := testVectors[0]
	c, err := NewCipher(v.k, v.t)
	if err != nil {
		b.Fatal("NewCipher: ", err)
	}
	out := make([]byte, len(v.out))
	b.SetBytes(int64(len(out)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Decrypt(out, v.out)
	}
}
