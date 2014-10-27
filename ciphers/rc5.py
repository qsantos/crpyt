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
