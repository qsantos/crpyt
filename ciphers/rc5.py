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

w = 32
u = w//8
def ROL(n,k):
	k %= w
	n %= 1<<w
	return ((n<<k)%(1<<w)) | (n>>(w-k))

# Reference: *The RC5 Encryption Algorithm* by Ronald Rivest
class RC5(object):
	def __init__(self, K, r=12):
		L = bytes_to_words(K, u, 'little')

		t = 2*r+2
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
		A, B = X

		if revert:
			for i in reversed(range(self.r)):
				B = ROL(B-S[2*i+3], -A)^A
				A = ROL(A-S[2*i+2], -B)^B
			B -= S[1]
			A -= S[0]
		else:
			A += S[0]
			B += S[1]
			for i in range(self.r):
				A = ROL(A^B, B)+S[2*i+2]
				B = ROL(A^B, A)+S[2*i+3]

		X = words_to_bytes([A,B], 4, 'little')
		return X
