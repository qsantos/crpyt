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

class RC4(object):
	def __init__(self, key):
		key = [ord(c) for c in key]
		S = list(range(256))
		l = len(key)
		j = 0
		for i in range(256):
			j = (j+S[i]+key[i%l]) % 256
			S[i], S[j] = S[j], S[i]
		self.S = S
		self.i = 0
		self.j = 0

	def byte(self):
		S, i, j = self.S, self.i, self.j
		i = (i+   1) % 256
		j = (j+S[i]) % 256
		S[i], S[j] = S[j], S[i]
		self.i, self.j = i, j
		return S[(S[i]+S[j]) % 256]

	def gen(self, n):
		return "".join("%.2x" % self.byte() for _ in range(n))
