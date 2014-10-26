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

# Reference: FIPS PUB 180-4
class SHA256(Digest):
	def __init__(self):
		super(SHA256,self).__init__(64, 4, 'big')
		self.H = [
			0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
			0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
		]

	def block(self, X):
		(A,B,C,D,E,F,G,H) = self.H

		maskint = 0xffffffff
		def ROT(x,n): return (x >> n) | ((x << (32-n)) & maskint)
		def Ch(x,y,z):  return (x & y) | ((x^maskint) & z)
		def Maj(x,y,z): return (x & y) | (x & z) | (y & z)
		def SHR(x,n):   return x >> n
		def Sum0(x):    return ROT(x, 2) ^ ROT(x,13) ^ ROT(x,22)
		def Sum1(x):    return ROT(x, 6) ^ ROT(x,11) ^ ROT(x,25)
		def Sigma0(x):  return ROT(x, 7) ^ ROT(x,18) ^ SHR(x, 3)
		def Sigma1(x):  return ROT(x,17) ^ ROT(x,19) ^ SHR(x,10)

		W = X + [0] * 48
		for t in range(16,64):
			W[t] = (Sigma1(W[t-2]) + W[t-7] + Sigma0(W[t-15]) + W[t-16]) & maskint

		for t in range(64):
			T1 = Sum1(E) + Ch (E,F,G) + self.K[t] + W[t] + H
			T2 = Sum0(A) + Maj(A,B,C)
			(A,B,C,D,E,F,G,H) = ((T1+T2)&maskint,A,B,C,(D+T1)&maskint,E,F,G)

		self.H = [(oi + ni) & maskint for (oi,ni) in zip(self.H, [A,B,C,D,E,F,G,H])]

	K = [
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
	]

# Reference: FIPS PUB 180-4
class SHA224(SHA256):
	def __init__(self):
		super(SHA224,self).__init__()
		self.H = [
			0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
			0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4,
		]
	def final(self):
		return super(SHA224,self).final()[:28]
