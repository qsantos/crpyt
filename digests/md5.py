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

# Reference: RFC 1321
class MD5(Digest):
	def __init__(self):
		super(MD5,self).__init__(64)
		self.H = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]

	def block(self, X):
		global A, B, C, D
		(A,B,C,D) = self.H

		maskint = 0xffffffff
		def ROT(x,n): return ((x << n) & maskint) | (x >> (32-n))
		def F(X,Y,Z): return (X & Y) | ((X^maskint) & Z)
		def G(X,Y,Z): return (X & Z) | (Y & (Z^maskint))
		def H(X,Y,Z): return X ^ Y ^ Z
		def I(X,Y,Z): return Y ^ (X | (Z^maskint))
		def OP(f,i,k,s):
			global A, B, C, D
			A = (B + ROT((A + f(B,C,D) + X[k] + self.T[i]) & maskint, s)) & maskint
			(A,B,C,D) = (D,A,B,C)

		i = 0
		for j in [0,4,8,12]:
			for k,s in zip([0,1,2,3],[7,12,17,22]):
				OP(F,i,(j+k)%16,s)
				i += 1

		for j in [1,5,9,13]:
			for k,s in zip([0,5,10,15],[5,9,14,20]):
				OP(G,i,(j+k)%16,s)
				i += 1

		for j in [5,1,13,9]:
			for k,s in zip([0,3,6,9],[4,11,16,23]):
				OP(H,i,(j+k)%16,s)
				i += 1

		for j in [0,12,8,4]:
			for k,s in zip([0,7,14,21],[6,10,15,21]):
				OP(I,i,(j+k)%16,s)
				i += 1

		self.H = [(oi + ni) & maskint for (oi,ni) in zip(self.H, [A,B,C,D])]

	T = [
		0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
		0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
		0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
		0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,

		0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
		0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
		0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
		0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,

		0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
		0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
		0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
		0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,

		0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
		0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
		0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
		0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
	]
