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
class SHA512(Digest):
	def __init__(self):
		super(SHA512,self).__init__(128, 8, 'big')
		self.H = [
			0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
			0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
			0x510e527fade682d1, 0x9b05688c2b3e6c1f,
			0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
		]

	def block(self, X):
		(A,B,C,D,E,F,G,H) = self.H

		maskint = 0xffffffffffffffff
		def ROT(x,n): return (x >> n) | ((x << (64-n)) & maskint)
		def Ch(x,y,z):  return (x & y) | ((x^maskint) & z)
		def Maj(x,y,z): return (x & y) | (x & z) | (y & z)
		def SHR(x,n):   return x >> n
		def Sum0(x):    return ROT(x,28) ^ ROT(x,34) ^ ROT(x,39)
		def Sum1(x):    return ROT(x,14) ^ ROT(x,18) ^ ROT(x,41)
		def Sigma0(x):  return ROT(x, 1) ^ ROT(x, 8) ^ SHR(x, 7)
		def Sigma1(x):  return ROT(x,19) ^ ROT(x,61) ^ SHR(x, 6)

		W = X + [0] * 64
		for t in range(16,80):
			W[t] = (Sigma1(W[t-2]) + W[t-7] + Sigma0(W[t-15]) + W[t-16]) & maskint

		for t in range(80):
			T1 = (Sum1(E) + Ch (E,F,G) + self.K[t] + W[t] + H) & maskint
			T2 = (Sum0(A) + Maj(A,B,C)) & maskint
			(A,B,C,D,E,F,G,H) = ((T1+T2)&maskint,A,B,C,(D+T1)&maskint,E,F,G)

		self.H = [(oi + ni) & maskint for (oi,ni) in zip(self.H, [A,B,C,D,E,F,G,H])]

	K = [
		0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
		0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
		0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
		0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
		0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
		0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
		0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
		0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
		0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
		0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
		0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
		0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
		0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
		0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
		0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
		0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
		0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
		0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
		0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
		0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
	]

class SHA384(SHA512):
	def __init__(self):
		super(SHA384,self).__init__()
		self.H = [
			0xcbbb9d5dc1059ed8, 0x629a292a367cd507,
			0x9159015a3070dd17, 0x152fecd8f70e5939,
			0x67332667ffc00b31, 0x8eb44a8768581511,
			0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4,
		]
	def final(self):
		return super(SHA384,self).final()[:48]

class SHA512T224:
	def __init__(self):
		super().__init__()
		self.H = [
			0x8c3d37c819544da2, 0x73e1996689dcd4d6,
			0x1dfab7ae32ff9c82, 0x679dd514582f9fcf,
			0x0f6d2b697bd44da8, 0x77e36f7304c48942,
			0x3f9d85a86a1d36c8, 0x1112e6ad91d692a1,
		]
	def final(self):
		return super().final()[:28]

class SHA512T256:
	def __init__(self):
		super().__init__()
		self.H = [
			0x22312194fc2bf72c, 0x9f555fa3c84c64c2,
			0x2393b86b6f53b151, 0x963877195940eabd,
			0x96283ee2a88effe3, 0xbe5e1e2553863992,
			0x2b0199fc2c85b8aa, 0x0eb72ddc81c52ca2,
		]
	def final(self):
		return super().final()[:32]
