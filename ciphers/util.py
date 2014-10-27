def bits_to_word(L):
	return int(''.join([str(c) for c in L]), 2)

def word_to_bits(i, n=8):
	fmt = "{:0%ib}" % n
	return [int(c) for c in fmt.format(i)]

def words_to_bits(L, n=8):
	return [b for i in L for b in word_to_bits(i,n)]

def bits_to_words(L, n=8):
	return [bits_to_word(L[o:o+n]) for o in range(0,len(L),n)]


def bytes_to_words(L, ws, byteorder):
	l = len(L)
	R = [0]*(l//ws)
	it = range(l) if byteorder == 'big' else reversed(range(l))
	for i in it:
		R[i//ws] = (R[i//ws] << 8) | L[i]
	return R

def words_to_bytes(L, ws, byteorder):
	R = []
	for w in L:
		W = []
		for i in range(ws):
			W.append(w&0xff)
			w >>= 8
		R += W if byteorder == 'little' else W[::-1]
	return R


def hexa_to_bytes(s):
	return [int(s[o:o+2],16) for o in range(0,len(s),2)]

def bytes_to_hexa(L):
	return "".join("%.2x" % b for b in L)
