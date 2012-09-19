// Copyright 2012 Dmitry Chestnykh. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package threefish

import "encoding/binary"

// Rotation constants.
var rotK = [8][4]uint{
	{46, 36, 19, 37},
	{33, 27, 14, 42},
	{17, 49, 36, 39},
	{44, 9, 54, 56},
	{39, 30, 34, 24},
	{13, 50, 10, 17},
	{25, 29, 39, 43},
	{8, 35, 56, 22},
}

func rotl(x uint64, r uint) uint64 { return x<<r | x>>(64-r) }
func rotr(x uint64, r uint) uint64 { return x>>r | x<<(64-r) }

func mix(a, b *uint64, r uint) {
	*a += *b
	*b = rotl(*b, r) ^ *a
}

func unmix(a, b *uint64, r uint) {
	*b = rotr(*b^*a, r)
	*a -= *b
}

func encMix(v *[8]uint64, i0, i1, i2, i3, i4, i5, i6, i7, r int) {
	mix(&v[i0], &v[i1], rotK[r][0])
	mix(&v[i2], &v[i3], rotK[r][1])
	mix(&v[i4], &v[i5], rotK[r][2])
	mix(&v[i6], &v[i7], rotK[r][3])
}

func decUnmix(v *[8]uint64, i0, i1, i2, i3, i4, i5, i6, i7, r int) {
	unmix(&v[i0], &v[i1], rotK[r][0])
	unmix(&v[i2], &v[i3], rotK[r][1])
	unmix(&v[i4], &v[i5], rotK[r][2])
	unmix(&v[i6], &v[i7], rotK[r][3])
}

func encInject(v *[8]uint64, ks *[9]uint64, ts *[3]uint64, r int) {
	v[0] += ks[(r+1)%9]
	v[1] += ks[(r+2)%9]
	v[2] += ks[(r+3)%9]
	v[3] += ks[(r+4)%9]
	v[4] += ks[(r+5)%9]
	v[5] += ks[(r+6)%9] + ts[(r+1)%3]
	v[6] += ks[(r+7)%9] + ts[(r+2)%3]
	v[7] += ks[(r+8)%9] + uint64(r) + 1
}

func decInject(v *[8]uint64, ks *[9]uint64, ts *[3]uint64, r int) {
	v[0] -= ks[(r+1)%9]
	v[1] -= ks[(r+2)%9]
	v[2] -= ks[(r+3)%9]
	v[3] -= ks[(r+4)%9]
	v[4] -= ks[(r+5)%9]
	v[5] -= ks[(r+6)%9] + ts[(r+1)%3]
	v[6] -= ks[(r+7)%9] + ts[(r+2)%3]
	v[7] -= ks[(r+8)%9] + uint64(r) + 1
}

func encryptBlock(ks *[9]uint64, ts *[3]uint64, dst, src []byte) {
	var v [8]uint64
	for i := 0; i < 8; i++ {
		v[i] = binary.LittleEndian.Uint64(src[i*8:])
	}
	encInject(&v, ks, ts, -1)
	for r := 0; r <= 8; r++ {
		encMix(&v, 0, 1, 2, 3, 4, 5, 6, 7, 0)
		encMix(&v, 2, 1, 4, 7, 6, 5, 0, 3, 1)
		encMix(&v, 4, 1, 6, 3, 0, 5, 2, 7, 2)
		encMix(&v, 6, 1, 0, 7, 2, 5, 4, 3, 3)
		encInject(&v, ks, ts, 2*r)
		encMix(&v, 0, 1, 2, 3, 4, 5, 6, 7, 4)
		encMix(&v, 2, 1, 4, 7, 6, 5, 0, 3, 5)
		encMix(&v, 4, 1, 6, 3, 0, 5, 2, 7, 6)
		encMix(&v, 6, 1, 0, 7, 2, 5, 4, 3, 7)
		encInject(&v, ks, ts, 2*r+1)
	}
	for i := 0; i < 8; i++ {
		binary.LittleEndian.PutUint64(dst[i*8:], v[i])
	}
}

func decryptBlock(ks *[9]uint64, ts *[3]uint64, dst, src []byte) {
	var v [8]uint64
	for i := 0; i < 8; i++ {
		v[i] = binary.LittleEndian.Uint64(src[i*8:])
	}
	for r := 8; r >= 0; r-- {
		decInject(&v, ks, ts, 2*r+1)
		decUnmix(&v, 6, 1, 0, 7, 2, 5, 4, 3, 7)
		decUnmix(&v, 4, 1, 6, 3, 0, 5, 2, 7, 6)
		decUnmix(&v, 2, 1, 4, 7, 6, 5, 0, 3, 5)
		decUnmix(&v, 0, 1, 2, 3, 4, 5, 6, 7, 4)
		decInject(&v, ks, ts, 2*r)
		decUnmix(&v, 6, 1, 0, 7, 2, 5, 4, 3, 3)
		decUnmix(&v, 4, 1, 6, 3, 0, 5, 2, 7, 2)
		decUnmix(&v, 2, 1, 4, 7, 6, 5, 0, 3, 1)
		decUnmix(&v, 0, 1, 2, 3, 4, 5, 6, 7, 0)
	}
	decInject(&v, ks, ts, -1)

	for i := 0; i < 8; i++ {
		binary.LittleEndian.PutUint64(dst[i*8:], v[i])
	}
}
