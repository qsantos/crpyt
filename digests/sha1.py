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

# Reference: RFC 3174, FIPS PUB 180-4
class SHA1(Digest):
	def __init__(self):
		super(SHA1,self).__init__(64, 4, 'big')
		self.H = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0]

	def block(self, X):
		global A, B, C, D, E
		(A,B,C,D,E) = self.H

		maskint = 0xffffffff
		def ROT(x,n): return ((x << n) & maskint) | (x >> (32-n))
		def F(X,Y,Z): return (X & Y) | ((X^maskint) & Z)
		def G(X,Y,Z): return X ^ Y ^ Z
		def H(X,Y,Z): return (X & Y) | (X & Z) | (Y & Z)

		W = X + [0] * 64
		for t in range(16,80):
			W[t] = ROT(W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16], 1)

		def OP(f,t,i):
			global A, B, C, D, E
			T = (ROT(A,5) + f(B,C,D) + E + W[t] + i) & maskint
			(A,B,C,D,E) = (T, A, ROT(B,30), C, D)

		for t in range( 0, 20): OP(F, t, 0x5a827999);
		for t in range(20, 40): OP(G, t, 0x6ed9eba1);
		for t in range(40, 60): OP(H, t, 0x8f1bbcdc);
		for t in range(60, 80): OP(G, t, 0xca62c1d6);

		self.H = [(oi + ni) & maskint for (oi,ni) in zip(self.H, [A,B,C,D,E])]
