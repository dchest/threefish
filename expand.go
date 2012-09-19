// Copyright 2012 Dmitry Chestnykh. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package threefish

const keyScheduleConst = 0x1bd11bdaa9fc1a22

func expandKey(ks *[9]uint64, k []byte) {
	ks[0] = uint64(k[0]) | uint64(k[1])<<8 | uint64(k[2])<<16 | uint64(k[3])<<24 |
		uint64(k[4])<<32 | uint64(k[5])<<40 | uint64(k[6])<<48 | uint64(k[7])<<56
	ks[1] = uint64(k[8]) | uint64(k[9])<<8 | uint64(k[10])<<16 | uint64(k[11])<<24 |
		uint64(k[12])<<32 | uint64(k[13])<<40 | uint64(k[14])<<48 | uint64(k[15])<<56
	ks[2] = uint64(k[16]) | uint64(k[17])<<8 | uint64(k[18])<<16 | uint64(k[19])<<24 |
		uint64(k[20])<<32 | uint64(k[21])<<40 | uint64(k[22])<<48 | uint64(k[23])<<56
	ks[3] = uint64(k[24]) | uint64(k[25])<<8 | uint64(k[26])<<16 | uint64(k[27])<<24 |
		uint64(k[28])<<32 | uint64(k[29])<<40 | uint64(k[30])<<48 | uint64(k[31])<<56
	ks[4] = uint64(k[32]) | uint64(k[33])<<8 | uint64(k[34])<<16 | uint64(k[35])<<24 |
		uint64(k[36])<<32 | uint64(k[37])<<40 | uint64(k[38])<<48 | uint64(k[39])<<56
	ks[5] = uint64(k[40]) | uint64(k[41])<<8 | uint64(k[42])<<16 | uint64(k[43])<<24 |
		uint64(k[44])<<32 | uint64(k[45])<<40 | uint64(k[46])<<48 | uint64(k[47])<<56
	ks[6] = uint64(k[48]) | uint64(k[49])<<8 | uint64(k[50])<<16 | uint64(k[51])<<24 |
		uint64(k[52])<<32 | uint64(k[53])<<40 | uint64(k[54])<<48 | uint64(k[55])<<56
	ks[7] = uint64(k[56]) | uint64(k[57])<<8 | uint64(k[58])<<16 | uint64(k[59])<<24 |
		uint64(k[60])<<32 | uint64(k[61])<<40 | uint64(k[62])<<48 | uint64(k[63])<<56
	ks[8] = keyScheduleConst ^ ks[0] ^ ks[1] ^ ks[2] ^ ks[3] ^ ks[4] ^
		ks[5] ^ ks[6] ^ ks[7]
}

func expandTweak(ts *[3]uint64, t []byte) {
	ts[0] = uint64(t[0]) | uint64(t[1])<<8 | uint64(t[2])<<16 | uint64(t[3])<<24 |
		uint64(t[4])<<32 | uint64(t[5])<<40 | uint64(t[6])<<48 | uint64(t[7])<<56
	ts[1] = uint64(t[8]) | uint64(t[9])<<8 | uint64(t[10])<<16 | uint64(t[11])<<24 |
		uint64(t[12])<<32 | uint64(t[13])<<40 | uint64(t[14])<<48 | uint64(t[15])<<56
	ts[2] = ts[0] ^ ts[1]
}
