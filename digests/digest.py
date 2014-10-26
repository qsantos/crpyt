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

def int_from_list(l, byteorder):
	if byteorder == 'little':
		return int_from_list(l[::-1], 'big')
	r = 0
	for b in l:
		r *= 256
		r += b
	return r

def int_to_list(integer, length, byteorder):
	if byteorder == 'big':
		return int_to_list(integer, length, 'little')[::-1]
	r = []
	for i in range(length):
		r += [integer % 256]
		integer //= 256
	return r

class Digest(object):
	def __init__(self, blocksize, wordsize=4, endian='little'):
		self.blocksize = blocksize
		self.wordsize  = wordsize
		self.endian    = endian

	def pad(self, l):
		rem = self.blocksize-2*self.wordsize-1 - (l%self.blocksize)
		if rem < 0:
			rem += self.blocksize
		pad = [128] + [0]*rem + int_to_list(l*8, 2*self.wordsize, byteorder=self.endian)
		return pad

	def final(self):
		return self.words_to_bytes(self.H)

	def hash(self, M):
		M = [ord(c) for c in M] + self.pad(len(M))

		blocks = [M[o:o+self.blocksize] for o in range(0,len(M),self.blocksize)]
		for block in blocks:
			X = self.bytes_to_words(block)
			self.block(X)

		return ''.join("{:02x}".format(c) for c in self.final())

	def bytes_to_words(self, l):
		return [int_from_list(l[o:o+self.wordsize], byteorder=self.endian) for o in range(0,len(l),self.wordsize)]

	def words_to_bytes(self, l):
		return [b for w in l for b in int_to_list(w, self.wordsize, byteorder=self.endian)]
