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

from digest import Digest

# Reference: http://keccak.noekeon.org/
# (assume r % 8 == 0 and c % 8 == 0 and n % 8 == 0)
class Keccak(Digest):
	def __init__(self, r=1440, c=160, n=1024, nr=24):
		w = (r+c) // 25
		super(Keccak,self).__init__(r//8, w//8)
		self.A = [[0]*5 for _ in range(5)]
		self.r = r
		self.c = c
		self.n = n
		self.nr = nr
		self.w = w

	def pad(self, l):
		rem = self.blocksize-1 - (l%self.blocksize)
		pad = [1] + [0]*rem
		pad[-1] ^= 0x80
		return pad

	def final(self):
		Z = []
		for i in range(0,self.n,self.r):
			T = [self.A[x][y] for y in range(5) for x in range(5)]
			T = self.words_to_bytes(T)
			Z += T[:self.blocksize]
			self.block()
		return Z[:self.n//8]

	def block(self, X=[0]*25):
		X += [0]*(self.c//self.w)
		A = self.A
		A = [[A[x][y] ^ X[x+5*y] for y in range(5)] for x in range(5)]

		maskint = (1<<self.w)-1
		def ROT(x,n): n %= self.w; return ((x << n) & maskint) | (x >> (self.w-n))

		for i in self.RC[:self.nr]:
			C = [Ai[0] ^ Ai[1] ^ Ai[2] ^ Ai[3] ^ Ai[4] for Ai in A]
			D = [C[(x-1)%5] ^ ROT(C[(x+1)%5],1) for x in range(5)]
			A = [[a ^ d for a in Ai] for (Ai,d) in zip(A,D)]

			B = [[0]*5 for _ in range(5)]
			for x in range(5):
				for y in range(5):
					B[y][(2*x+3*y)%5] = ROT(A[x][y], self.R[x][y])

			A = [[B[x][y] ^ ((B[(x+1)%5][y]^maskint) & B[(x+2)%5][y]) for y in range(5)] for x in range(5)]

			A[0][0] = (A[0][0] ^ i) & maskint

		self.A = A

	RC = [
		0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
		0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
		0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
		0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
		0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
		0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
	]

	R = [
		[ 0, 36,  3, 41, 18],
		[ 1, 44, 10, 45,  2],
		[62,  6, 43, 15, 61],
		[28, 55, 25, 21, 56],
		[27, 20, 39,  8, 14],
	]

class KeccakNoPad(Keccak):
	def pad(self, l):
		return []

class Keccak224(Keccak):
	def __init__(self): super(Keccak224,self).__init__(1156, 448, 224)
class Keccak256(Keccak):
	def __init__(self): super(Keccak256,self).__init__(1088, 512, 256)
class Keccak384(Keccak):
	def __init__(self): super(Keccak384,self).__init__( 832, 768, 384)
class Keccak512(Keccak):
	def __init__(self): super(Keccak512,self).__init__( 576,1024, 512)

class SHA3(Keccak):
	def pad(self, l):
		rem = self.blocksize-2 - (l%self.blocksize)
		pad = [6] + [0]*rem + [0x80]
		return pad

class SHA3_224(SHA3):
	def __init__(self): super(SHA3_224,self).__init__(1156, 448, 224)
class SHA3_256(SHA3):
	def __init__(self): super(SHA3_256,self).__init__(1088, 512, 256)
class SHA3_384(SHA3):
	def __init__(self): super(SHA3_384,self).__init__( 832, 768, 384)
class SHA3_512(SHA3):
	def __init__(self): super(SHA3_512,self).__init__( 576,1024, 512)

class SHAKE(Keccak):
	def pad(self, l):
		rem = self.blocksize-2 - (l%self.blocksize)
		pad = [0x1f] + [0]*rem + [0x80]
		return pad

class SHAKE128(SHAKE):
	def __init__(self, d): super(SHAKE128,self).__init__(1344, 256, d)
class SHAKE256(SHAKE):
	def __init__(self, d): super(SHAKE256,self).__init__(1088, 512, d)
