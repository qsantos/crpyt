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

w = 32
r = 12
b = 16
c =  4
t = 26
u = w//8
maskint = (1<<w)-1
def ROL(n,k):
	n &= maskint
	k %= w
	return ((n<<k)&maskint) | (n>>(w-k))

# Reference: *The RC5 Encryption Algorithm* by Ronald Rivest
class RC5(object):
	def __init__(self, K):
		# 8-to-w bits
		L = [0]*c
		for i in reversed(range(b)):
			L[i//u] = (L[i//u]<<8) | K[i]

		P64 = 0xb7e151628aed2a6b
		Q64 = 0x9e3779b97f4a7c15
		P, Q = P64>>(64-w)|1, Q64>>(64-w)|1

		S = [(P+Q*i)&maskint for i in range(t)]

		A, B = 0, 0
		for k in range(3*max(t,c)):
			i, j = k%t, k%c
			A = S[i] = ROL(S[i]+A+B,3)
			B = L[j] = ROL(L[j]+A+B,A+B)

		self.S = S

	def block(self, X, revert=False):
		X = [X[4*i] | (X[4*i+1]<<8) | (X[4*i+2]<<16) | (X[4*i+3]<<24) for i in range(2)]
		S = self.S
		A, B = X

		if revert:
			for i in reversed(range(r)):
				B = ROL(B-S[2*i+3], -A)^A
				A = ROL(A-S[2*i+2], -B)^B
			B -= S[1]
			A -= S[0]
		else:
			A = (A+S[0])&maskint
			B = (B+S[1])&maskint
			for i in range(r):
				A = ( ROL(A^B, B)+S[2*i+2] )&maskint
				B = ( ROL(A^B, A)+S[2*i+3] )&maskint

		def f(x):
			r = []
			for i in range(4):
				r.append(x&0xff)
				x >>= 8
			return r
		X = f(A) + f(B)
		return X

K = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
M = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
C = [0x21, 0xa5, 0xdb, 0xee, 0x15, 0x4b, 0x8f, 0x6d]
assert RC5(K).block(M, False) == C
assert RC5(K).block(C, True)  == M

K = [0x91, 0x5f, 0x46, 0x19, 0xbe, 0x41, 0xb2, 0x51, 0x63, 0x55, 0xa5, 0x01, 0x10, 0xa9, 0xce, 0x91]
M = [0x21, 0xa5, 0xdb, 0xee, 0x15, 0x4b, 0x8f, 0x6d]
C = [0xf7, 0xc0, 0x13, 0xac, 0x5b, 0x2b, 0x89, 0x52]
assert RC5(K).block(M, False) == C
assert RC5(K).block(C, True)  == M

K = [0x78, 0x33, 0x48, 0xe7, 0x5a, 0xeb, 0x0f, 0x2f, 0xd7, 0xb1, 0x69, 0xbb, 0x8d, 0xc1, 0x67, 0x87]
M = [0xf7, 0xc0, 0x13, 0xac, 0x5b, 0x2b, 0x89, 0x52]
C = [0x2f, 0x42, 0xb3, 0xb7, 0x03, 0x69, 0xfc, 0x92]
assert RC5(K).block(M, False) == C
assert RC5(K).block(C, True)  == M

K = [0xdc, 0x49, 0xdb, 0x13, 0x75, 0xa5, 0x58, 0x4f, 0x64, 0x85, 0xb4, 0x13, 0xb5, 0xf1, 0x2b, 0xaf]
M = [0x2f, 0x42, 0xb3, 0xb7, 0x03, 0x69, 0xfc, 0x92]
C = [0x65, 0xC1, 0x78, 0xB2, 0x84, 0xD1, 0x97, 0xCC]
assert RC5(K).block(M, False) == C
assert RC5(K).block(C, True)  == M

K = [0x52, 0x69, 0xf1, 0x49, 0xd4, 0x1b, 0xa0, 0x15, 0x24, 0x97, 0x57, 0x4d, 0x7f, 0x15, 0x31, 0x25]
M = [0x65, 0xC1, 0x78, 0xB2, 0x84, 0xD1, 0x97, 0xCC]
C = [0xEB, 0x44, 0xE4, 0x15, 0xDA, 0x31, 0x98, 0x24]
assert RC5(K).block(M, False) == C
assert RC5(K).block(C, True)  == M
