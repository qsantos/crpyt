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
from des_data import *

def subst(P,l,X):
	return [X[P[b]] for b in range(l)]

def f(R, K):
	cur = subst(E, 48, R)
	cur = [a^b for (a,b) in zip(cur,K)]

	cur = bits_to_words(cur, 6)
	cur = [S[i][cur[i]] for i in range(8)]
	cur = words_to_bits(cur, 4)

	return subst(P, 32, cur)

def shift(l, s):
	n = len(l)
	return [l[(i+s)%n] for i in range(n)]

# Reference: FIPS PUB 46-3
class DES(object):
	def __init__(self, key):
		self.key = key

	def block(self, X, revert=False):
		key = self.key
		LR = subst(IP, 64, X)
		L, R = LR[:32], LR[32:]

		CD = subst(PC1, 56, key)
		for i in range(16):
			if revert:
				s = -shifts[15-i]
				K = subst(PC2, 48, CD)
				CD = shift(CD[:28], s) + shift(CD[28:], s)
			else:
				s = shifts[i]
				CD = shift(CD[:28], s) + shift(CD[28:], s)
				K = subst(PC2, 48, CD)

			L, R = list(R), [l^r for (l,r) in zip(L,f(R,K))]

		return subst(IPR, 64, R+L)
