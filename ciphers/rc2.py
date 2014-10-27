# crpyt: toy cryptographic python library
# Copyright (C) 2014 Quentin SANTOS
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# END LICENCE

from util import *

PITABLE = [
	0xd9,0x78,0xf9,0xc4,0x19,0xdd,0xb5,0xed,0x28,0xe9,0xfd,0x79,0x4a,0xa0,0xd8,0x9d,
	0xc6,0x7e,0x37,0x83,0x2b,0x76,0x53,0x8e,0x62,0x4c,0x64,0x88,0x44,0x8b,0xfb,0xa2,
	0x17,0x9a,0x59,0xf5,0x87,0xb3,0x4f,0x13,0x61,0x45,0x6d,0x8d,0x09,0x81,0x7d,0x32,
	0xbd,0x8f,0x40,0xeb,0x86,0xb7,0x7b,0x0b,0xf0,0x95,0x21,0x22,0x5c,0x6b,0x4e,0x82,
	0x54,0xd6,0x65,0x93,0xce,0x60,0xb2,0x1c,0x73,0x56,0xc0,0x14,0xa7,0x8c,0xf1,0xdc,
	0x12,0x75,0xca,0x1f,0x3b,0xbe,0xe4,0xd1,0x42,0x3d,0xd4,0x30,0xa3,0x3c,0xb6,0x26,
	0x6f,0xbf,0x0e,0xda,0x46,0x69,0x07,0x57,0x27,0xf2,0x1d,0x9b,0xbc,0x94,0x43,0x03,
	0xf8,0x11,0xc7,0xf6,0x90,0xef,0x3e,0xe7,0x06,0xc3,0xd5,0x2f,0xc8,0x66,0x1e,0xd7,
	0x08,0xe8,0xea,0xde,0x80,0x52,0xee,0xf7,0x84,0xaa,0x72,0xac,0x35,0x4d,0x6a,0x2a,
	0x96,0x1a,0xd2,0x71,0x5a,0x15,0x49,0x74,0x4b,0x9f,0xd0,0x5e,0x04,0x18,0xa4,0xec,
	0xc2,0xe0,0x41,0x6e,0x0f,0x51,0xcb,0xcc,0x24,0x91,0xaf,0x50,0xa1,0xf4,0x70,0x39,
	0x99,0x7c,0x3a,0x85,0x23,0xb8,0xb4,0x7a,0xfc,0x02,0x36,0x5b,0x25,0x55,0x97,0x31,
	0x2d,0x5d,0xfa,0x98,0xe3,0x8a,0x92,0xae,0x05,0xdf,0x29,0x10,0x67,0x6c,0xba,0xc9,
	0xd3,0x00,0xe6,0xcf,0xe1,0x9e,0xa8,0x2c,0x63,0x16,0x01,0x3f,0x58,0xe2,0x89,0xa9,
	0x0d,0x38,0x34,0x1b,0xab,0x33,0xff,0xb0,0xbb,0x48,0x0c,0x5f,0xb9,0xb1,0xcd,0x2e,
	0xc5,0xf3,0xdb,0x47,0xe5,0xa5,0x9c,0x77,0x0a,0xa6,0x20,0x68,0xfe,0x7f,0xc1,0xad,
]

maskint = 0xffff
def ROL(x,k): return ((x<<k)&maskint) | (x>>(16-k))
def ROR(x,k): return ((x>>k)&maskint) | (x<<(16-k))

# Reference: RFC 2268
class RC2(object):
	def __init__(self, key, bits=None):
		T = len(key)
		T1 = bits if bits is not None else 8*T
		T8 = (T1+7)//8
		TM = 0xff >> (-T1%8)

		L = key + [0]*(128-len(key))

		for i in range(T, 128):
			L[i] = PITABLE[(L[i-1]+L[i-T])%256]

		L[128-T8] = PITABLE[L[128-T8] & TM]

		for i in reversed(range(128-T8)):
			L[i] = PITABLE[L[i+1] ^ L[i+T8]]

		self.K = bytes_to_words(L, 2, 'little')

	def mix(self, R, i):
		t = R[i]
		t += self.K[self.j]
		t += R[i-2] &  R[i-1]
		t += R[i-3] & (R[i-1]^maskint)
		t &= maskint
		t = ROL(t,[1,2,3,5][i])
		R[i] = t
		self.j += 1

	def mash(self, R, i):
		R[i] = (R[i] + self.K[R[i-1] & 0x3f]) & maskint

	def mixround(self, R):
		for i in range(4):
			self.mix(R, i)

	def mashround(self, R):
		for i in range(4):
			self.mash(R, i)

	def invmix(self, R, i):
		self.j -= 1
		t = R[i]
		t = ROR(t,[1,2,3,5][i])
		t -= R[i-3] & (R[i-1]^maskint)
		t -= R[i-2] &  R[i-1]
		t -= self.K[self.j]
		t &= maskint
		R[i] = t

	def invmash(self, R, i):
		R[i] = (R[i] - self.K[R[i-1] & 0x3f]) & maskint

	def invmixround(self, R):
		for i in reversed(range(4)):
			self.invmix(R, i)

	def invmashround(self, R):
		for i in reversed(range(4)):
			self.invmash(R, i)

	def block(self, X, revert=False):
		R = bytes_to_words(X, 2, 'little')

		if revert:
			self.j = 64
			for i in range(5):
				self.invmixround(R)
			self.invmashround(R)
			for i in range(6):
				self.invmixround(R)
			self.invmashround(R)
			for i in range(5):
				self.invmixround(R)
		else:
			self.j = 0
			for i in range(5):
				self.mixround(R)
			self.mashround(R)
			for i in range(6):
				self.mixround(R)
			self.mashround(R)
			for i in range(5):
				self.mixround(R)

		X = words_to_bytes(R, 2, 'little')
		return X

def hexa(K, M, b):
	K = [int(K[o:o+2],16) for o in range(0,len(K),2)]
	M = [int(M[o:o+2],16) for o in range(0,len(M),2)]
	C = RC2(K,b).block(M)
	s = "".join("%.2x" % c for c in C)
	return s
