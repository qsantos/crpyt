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

from rijndael_data import *

def AddRoundKey(state, w): return [a^b for (a,b) in zip(state,w)]

def    SubBytes(state): return [   SBox[a] for a in state]
def InvSubBytes(state): return [invSBox[a] for a in state]

def    ShiftRows(state): return [state[4*((j+i)%4)+i] for j in range(4) for i in range(4)]
def InvShiftRows(state): return [state[4*((j-i)%4)+i] for j in range(4) for i in range(4)]

def prod32(a, b):
	return [
		dot8[a[0]][b[0]] ^ dot8[a[3]][b[1]] ^ dot8[a[2]][b[2]] ^ dot8[a[1]][b[3]],
		dot8[a[1]][b[0]] ^ dot8[a[0]][b[1]] ^ dot8[a[3]][b[2]] ^ dot8[a[2]][b[3]],
		dot8[a[2]][b[0]] ^ dot8[a[1]][b[1]] ^ dot8[a[0]][b[2]] ^ dot8[a[3]][b[3]],
		dot8[a[3]][b[0]] ^ dot8[a[2]][b[1]] ^ dot8[a[1]][b[2]] ^ dot8[a[0]][b[3]],
	]

def    MixColumns(state): return [c for o in range(0,16,4) for c in prod32(state[o:o+4],[ 2, 1, 1, 3])]
def InvMixColumns(state): return [c for o in range(0,16,4) for c in prod32(state[o:o+4],[14, 9,13,11])]

# Reference: FIPS PUB 197, *AES Proposal* by Rijndael, Daemen and Rijman
def Rijndael(key, block, Nk, Nb, revert=False):
	Nr = [[10, 12, 14], [12, 12, 14], [14, 14, 14]][Nk//2-2][Nb//2-2]

	# key expansion
	w = key
	for i in range(Nk,4*(Nr+1)):
		m = w[-4:]
		if i % Nk == 0:
			m = m[1:] + m[:1]
			m = SubBytes(m)
			m[0] ^= Rcon[i//Nk-1]
		elif Nk > 6 and i % Nk == 4:
			m = SubBytes(m)
		prev = w[4*(i-Nk):4*(i-Nk)+4]
		w = w + [a^b for (a,b) in zip (prev,m)]
	w = [w[o:o+4*Nb] for o in range(0,len(w),4*Nb)]

	# encryption
	state = list(block)
	if revert:
		state = AddRoundKey (state, w[Nr])
		state = InvShiftRows(state)
		state = InvSubBytes (state)
		for i in reversed(range(1,Nr)):
			state = AddRoundKey  (state, w[i])
			state = InvMixColumns(state)
			state = InvShiftRows (state)
			state = InvSubBytes  (state)
		state = AddRoundKey(state, w[0])
	else:
		state = AddRoundKey(state, w[0]);
		for i in range(1,Nr):
			state = SubBytes   (state)
			state = ShiftRows  (state)
			state = MixColumns (state)
			state = AddRoundKey(state, w[i])
		state = SubBytes   (state)
		state = ShiftRows  (state)
		state = AddRoundKey(state, w[Nr])

	return state
