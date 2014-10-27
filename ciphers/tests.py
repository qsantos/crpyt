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

def test(A, M, C, K, *args, **kwargs):
	K = hexa_to_bytes(K)
	M = hexa_to_bytes(M)
	C = hexa_to_bytes(C)
	assert A(K,*args,**kwargs).block(M, False) == C
	assert A(K,*args,**kwargs).block(C, True)  == M

from des import *
test(DES, "3764384f8e76126b", "fedcba9876543210", "0123456789abcdef")

from rc2 import *
test(RC2, "0000000000000000", "ebb773f993278eff", "0000000000000000",                  63)
test(RC2, "ffffffffffffffff", "278b27e42e2f0d49", "ffffffffffffffff",                  64)
test(RC2, "1000000000000001", "30649edf9be7d2c2", "3000000000000000",                  64)
test(RC2, "0000000000000000", "61a8a244adacccf0", "88",                                64)
test(RC2, "0000000000000000", "6ccf4308974c267f", "88bca90e90875a",                    64)
test(RC2, "0000000000000000", "1a807d272bbe5db1", "88bca90e90875a7f0f79c384627bafb2",  64)
test(RC2, "0000000000000000", "2269552ab0f85ca6", "88bca90e90875a7f0f79c384627bafb2", 128)

from rc4 import *
assert RC4("Key"   ).gen(10) == "eb9f7781b734ca72a719"
assert RC4("Wiki"  ).gen( 6) == "6044db6d41b7"
assert RC4("Secret").gen( 8) == "04d46b053ca87b59"

from idea import *
test(IDEA, "0000010002000300", "fb112bed9801e56d", "01000200030004000500060007000800")

from rc5 import *
test(RC5, "0000000000000000", "21a5dbee154b8f6d", "00000000000000000000000000000000")
test(RC5, "21A5DBEE154B8F6D", "F7C013AC5B2B8952", "915F4619BE41B2516355A50110A9CE91")
test(RC5, "F7C013AC5B2B8952", "2F42B3B70369FC92", "783348E75AEB0F2FD7B169BB8DC16787")
test(RC5, "2F42B3B70369FC92", "65C178B284D197CC", "DC49DB1375A5584F6485B413B5F12BAF")
test(RC5, "65C178B284D197CC", "EB44E415DA319824", "5269F149D41BA0152497574D7F153125")

from rijndael import *
test(Rijndael, "00112233445566778899aabbccddeeff", "69c4e0d86a7b0430d8cdb78070b4c55a", "000102030405060708090a0b0c0d0e0f", 4, 4)
test(Rijndael, "00112233445566778899aabbccddeeff", "dda97ca4864cdfe06eaf70a0ec0d7191", "000102030405060708090a0b0c0d0e0f1011121314151617", 6, 4)
test(Rijndael, "00112233445566778899aabbccddeeff", "8ea2b7ca516745bfeafc49904b496089", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 8, 4)

from rc6 import *
test(RC6, "00000000000000000000000000000000", "8fc3a53656b1f778c129df4e9848a41e", "00000000000000000000000000000000")
test(RC6, "02132435465768798a9bacbdcedfe0f1", "524e192f4715c6231f51f6367ea43f18", "0123456789abcdef0112233445566778")
test(RC6, "00000000000000000000000000000000", "6cd61bcb190b30384e8a3f168690ae82", "000000000000000000000000000000000000000000000000")
test(RC6, "02132435465768798a9bacbdcedfe0f1", "688329d019e505041e52e92af95291d4", "0123456789abcdef0112233445566778899aabbccddeeff0")
test(RC6, "00000000000000000000000000000000", "8f5fbd0510d15fa893fa3fda6e857ec2", "0000000000000000000000000000000000000000000000000000000000000000")
test(RC6, "02132435465768798a9bacbdcedfe0f1", "c8241816f0d7e48920ad16a1674e5d48", "0123456789abcdef0112233445566778899aabbccddeeff01032547698badcfe")
