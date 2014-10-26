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

# Reference: RFC 1320
class MD4(Digest):
	def __init__(self):
		super(MD4,self).__init__(64)
		self.H = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]

	def block(self, X):
		global A, B, C, D
		(A,B,C,D) = self.H

		maskint = 0xffffffff
		def ROT(x,n): return ((x << n) & maskint) | (x >> (32-n))
		def F(X,Y,Z): return (X & Y) | ((X^maskint) & Z)
		def G(X,Y,Z): return (X & Y) | (X & Z) | (Y & Z)
		def H(X,Y,Z): return X ^ Y ^ Z
		def OP(f,i,k,s):
			global A, B, C, D
			A = ROT((A + f(B,C,D) + X[k] + i) & maskint, s)
			(A,B,C,D) = (D,A,B,C)

		for i in [0,4,8,12]:
			for (j,k) in zip([0,1,2, 3],[3,7,11,19]):
				OP(F, 0x00000000, i+j, k)

		for i in [0,1,2,3]:
			for (j,k) in zip([0,4,8,12],[3,5, 9,13]):
				OP(G, 0x5a827999, i+j, k)

		for i in [0,2,1,3]:
			for (j,k) in zip([0,8,4,12],[3,9,11,15]):
				OP(H, 0x6ed9eba1, i+j, k)

		self.H = [(oi + ni) & maskint for (oi,ni) in zip(self.H, [A,B,C,D])]
