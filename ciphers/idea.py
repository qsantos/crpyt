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

maskint = 0xffff
nrounds = 8
maxim = 0x10001

def mul(a, b):
	if   a == 0: return (1-b)&maskint
	elif b == 0: return (1-a)&maskint
	return (a*b)%maxim

def inv(a, b=maxim):
	r0, r1 = a, b
	s0, s1 = 1, 0
	t0, t1 = 0, 1
	while r1 != 0:
		q = r0 // r1
		r0, r1 = r1, r0 - q*r1
		s0, s1 = s1, s0 - q*s1
		t0, t1 = t1, t0 - q*t1
	return s0

# Reference: *On the Design Block and Security Ciphers* by Xuejia Lai and James Massey
class IDEA(object):
	def __init__(self, key):
		# key expansion
		S = key
		for i in range(8, 54):
			if   i % 8 == 6: a, b = i- 7, i-14
			elif i % 8 == 7: a, b = i-15, i-14
			else:            a, b = i- 7, i- 6
			t = (S[a]<<9) ^ (S[b]>>7)
			S.append(t & maskint)
		Z = [S[o:o+6] for o in range(0,len(S),6)]
		self.Z = Z

		# reverse key expansion
		DK = [[0]*6 for _ in range(nrounds+1)]
		for r in range(nrounds+1):
			DK[nrounds-r][0] = inv(Z[r][0])
			DK[nrounds-r][3] = inv(Z[r][3])
			if r == 0 or r == nrounds:
				DK[nrounds-r][1] = -Z[r][1]%0x10000
				DK[nrounds-r][2] = -Z[r][2]%0x10000
			else:
				DK[nrounds-r][1] = -Z[r][2]%0x10000
				DK[nrounds-r][2] = -Z[r][1]%0x10000
			DK[nrounds-r-1][4] = Z[r][4]
			DK[nrounds-r-1][5] = Z[r][5]
		self.DK = DK

	def block(self, X, revert=False):
		Z = self.DK if revert else self.Z
		x0, x1, x2, x3 = X
		for r in range(8):
			x0 = mul(x0, Z[r][0])
			x1 =    (x1+ Z[r][1])&maskint
			x2 =    (x2+ Z[r][2])&maskint
			x3 = mul(x3, Z[r][3])

			kk = mul(Z[r][4], x0^x2)
			t0 = mul(Z[r][5], (kk + (x1^x3))&maskint)
			t1 = (kk + t0)&maskint

			x0, x3 = x0^t0, x3^t1
			x1, x2 = x2^t0, x1^t1

		R = [
			mul(x0, Z[nrounds][0]),
			x2 + Z[nrounds][1] & maskint,
			x1 + Z[nrounds][2] & maskint,
			mul(x3, Z[nrounds][3]),
		]

		return R

K = [1, 2, 3, 4, 5, 6, 7, 8]
M = [0, 1, 2, 3]
C = [4603, 60715, 408, 28133]
assert IDEA(K).block(M, False) == C
assert IDEA(K).block(C, True)  == M
