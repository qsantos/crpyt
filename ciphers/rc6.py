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

lgw = 5
w = 1<<lgw
u = w//8
def ROL(n,k):
	k %= w
	n %= 1<<w
	return ((n<<k)%(1<<w)) | (n>>(w-k))

# Reference: *The RC6 Block Cipher" by Rivest, Robshaw, Sidney and Yin
class RC6(object):
	def __init__(self, K, r=20):
		L = bytes_to_words(K, u, 'little')

		t = 2*r+4
		P = ( 0xb7e151628aed2a6b >> (64-w) ) | 1
		Q = ( 0x9e3779b97f4a7c15 >> (64-w) ) | 1
		S = [P+Q*i for i in range(t)]

		A, B = 0, 0
		c = len(K)//u
		for k in range(3*max(t,c)):
			i, j = k%t, k%c
			A = S[i] = ROL(S[i]+A+B,3)
			B = L[j] = ROL(L[j]+A+B,A+B)

		self.r = r
		self.S = S

	def block(self, X, revert=False):
		X = bytes_to_words(X, u, 'little')
		S = self.S
		A, B, C, D = X

		if revert:
			C -= S[2*self.r+3]
			A -= S[2*self.r+2]
			for i in reversed(range(self.r)):
				A, B, C, D = D, A, B, C
				v = ROL(D*(2*D+1), lgw)
				t = ROL(B*(2*B+1), lgw)
				C = ROL(C-S[2*i+3], -t) ^ v
				A = ROL(A-S[2*i+2], -v) ^ t
			D -= S[1]
			B -= S[0]
		else:
			B += S[0]
			D += S[1]
			for i in range(self.r):
				t = ROL(B*(2*B+1), lgw)
				v = ROL(D*(2*D+1), lgw)
				A = ROL(A^t, v) + S[2*i+2]
				C = ROL(C^v, t) + S[2*i+3]
				A, B, C, D = B, C, D, A
			A += S[2*self.r+2]
			C += S[2*self.r+3]

		X = words_to_bytes([A,B,C,D], 4, 'little')
		return X
