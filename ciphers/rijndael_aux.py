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

# product
def prod8(a, b):
	r = 0
	while a != 0:
		if a % 2 == 1:
			r ^= b
		a >>= 1
		b <<= 1
	return r

# general modular reduction
def mod8(a, b=0x11b):
	# makes a mask for the first bit of a
	aa = a
	ma = 1
	while aa != 0:
		aa >>= 1
		ma <<= 1
	ma >>= 1;

	# pads b to a
	aa = a;
	bb = b;
	while bb != 0:
		if aa == 0:
			return a;
		aa >>= 1
		bb >>= 1

	pb = b
	while aa != 0:
		aa >>= 1
		pb <<= 1

	# applies xor on a with b to turn bits of a to zero
	while pb >= b:
		if a & ma != 0:
			a ^= pb
		pb >>= 1
		ma >>= 1

	return a

# simpler modular reduction for M=0x11b
def mod8(i):
	a = 1<<i
	M = 0x1b
	r = a & 0xff
	a >>= 8
	while a != 0:
		if a % 2:
			r ^= M
		a >>= 1
		M <<= 1
	return r

def dot8(a, b):
	r = 0
	M = 0x11b
	while a != 0:
		if a % 2 == 1:
			r ^= b
		a >>= 1
		b <<= 1
		if b & 0x100:
			b ^= M
	return r

# pre-compute Rcon
Rcon = map(mod8, range(10))
print("Rcon = [" + ", ".join("%#.2x"%x for x in Rcon) + "]")

print("")

# pre-compute dot8()
print("dot8 = [")
for a in range(256):
	print("\t[" + ",".join("%#.2x" % dot8(a,b) for b in range(15)) + "],")
print("]")
