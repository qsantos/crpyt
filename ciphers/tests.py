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

from des import *

def bytes_to_bits(l):
	l = [int_to_list(i,8) for i in l]
	l = [x for li in l for x in li]
	return l

def bits_to_bytes(l):
	return [list_to_int(l[o:o+8]) for o in range(0,len(l),8)]

key   = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]
block = [0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10]
out   = [0x37, 0x64, 0x38, 0x4f, 0x8e, 0x76, 0x12, 0x6b]
assert bits_to_bytes(DES(bytes_to_bits(key), bytes_to_bits(block), True)) == out


from rijndael import *

block = [0x11*i for i in range(16)]

# AES-128
out = [0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a]
assert Rijndael(list(range(16)), block, 4, 4, False) == out
assert Rijndael(list(range(16)), out,   4, 4, True ) == block


# AES-224
out = [0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91]
assert Rijndael(list(range(24)), block, 6, 4, False) == out
assert Rijndael(list(range(24)), out  , 6, 4, True)  == block

# AES-256
out = [0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89]
assert Rijndael(list(range(32)), block, 8, 4, False) == out
assert Rijndael(list(range(32)), out,   8, 4, True)  == block
