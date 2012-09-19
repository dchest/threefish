// Copyright 2012 Dmitry Chestnykh. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package threefish implements Threefish-512 block cipher as defined in 
// "The Skein Hash Function Family" paper version 1.3.
package threefish

import (
	"encoding/binary"
	"strconv"
)

const (
	// Block size in bytes.
	BlockSize = 64
	// Key size in bytes.
	KeySize = 64
	// Tweak size in bytes.
	TweakSize = 16
)

const keyScheduleConst = 0x1bd11bdaa9fc1a22

// Threefish is an instance of cipher using a particular key and tweak.
type Threefish struct {
	// Key schedule.
	ks [9]uint64
	// Tweak schedule.
	ts [3]uint64
}

type KeySizeError int

func (k KeySizeError) Error() string {
	return "threefish: invalid key size: " + strconv.Itoa(int(k))
}

type TweakSizeError int

func (t TweakSizeError) Error() string {
	return "threefish: invalid tweak size: " + strconv.Itoa(int(t))
}

func expandKey(ks *[9]uint64, k []byte) {
	ks[8] = keyScheduleConst
	for i := 0; i < 8; i++ {
		ks[i] = binary.LittleEndian.Uint64(k[i*8:])
		ks[8] ^= ks[i]
	}
}

func expandTweak(ts *[3]uint64, t []byte) {
	ts[2] = 0
	for i := 0; i < 2; i++ {
		ts[i] = binary.LittleEndian.Uint64(t[i*8:])
		ts[2] ^= ts[i]
	}
}

// NewCipher creates and returns a new Threefish cipher, compatible with
// cipher.Block interface. The key argument must be 64 bytes, tweak - 16 bytes.
func NewCipher(key []byte, tweak []byte) (*Threefish, error) {
	if len(key) != KeySize {
		return nil, KeySizeError(len(key))
	}
	if len(tweak) != TweakSize {
		return nil, TweakSizeError(len(tweak))
	}
	c := new(Threefish)
	expandKey(&c.ks, key)
	expandTweak(&c.ts, tweak)
	return c, nil
}

// SetTweak changes the tweak for Threefish cipher to the given value.
func (c *Threefish) SetTweak(tweak []byte) error {
	if len(tweak) != TweakSize {
		return TweakSizeError(len(tweak))
	}
	expandTweak(&c.ts, tweak)
	return nil
}

func (c *Threefish) BlockSize() int { return BlockSize }

func (c *Threefish) Encrypt(dst, src []byte) {
	encryptBlock(&c.ks, &c.ts, dst, src)
}

func (c *Threefish) Decrypt(dst, src []byte) {
	decryptBlock(&c.ks, &c.ts, dst, src)
}

// EncryptBlock encrypts a single block using with the given key and tweak.
func EncryptBlock(key, tweak, dst, src []byte) {
	var ks [9]uint64
	var ts [3]uint64
	expandKey(&ks, key)
	expandTweak(&ts, tweak)
	encryptBlock(&ks, &ts, dst, src)
}

// DecryptBlock decrypts a single block using the given key and tweak.
func DecryptBlock(key, tweak, dst, src []byte) {
	var ks [9]uint64
	var ts [3]uint64
	expandKey(&ks, key)
	expandTweak(&ts, tweak)
	decryptBlock(&ks, &ts, dst, src)
}
