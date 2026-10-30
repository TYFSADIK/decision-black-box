package blackbox

import "crypto/sha256"

// Tree is an RFC 6962 (Certificate Transparency) Merkle tree over entry hashes.
// Leaf = SHA256(0x00 || data), node = SHA256(0x01 || left || right).
type Tree struct{ leaves [][]byte }

func leafHash(d []byte) []byte { h := sha256.Sum256(append([]byte{0}, d...)); return h[:] }
func nodeHash(l, r []byte) []byte {
	b := make([]byte, 0, 65)
	b = append(append(append(b, 1), l...), r...)
	h := sha256.Sum256(b)
	return h[:]
}

func (t *Tree) Append(d []byte) { t.leaves = append(t.leaves, leafHash(d)) }
func (t *Tree) Size() uint64    { return uint64(len(t.leaves)) }
func (t *Tree) Root() []byte    { return mth(t.leaves) }

func split(n int) int {
	k := 1
	for k*2 < n {
		k *= 2
	}
	return k
}

func mth(l [][]byte) []byte {
	switch len(l) {
	case 0:
		h := sha256.Sum256(nil)
		return h[:]
	case 1:
		return l[0]
	}
	k := split(len(l))
	return nodeHash(mth(l[:k]), mth(l[k:]))
}

// Proof returns the audit path for leaf index i (RFC 6962 section 2.1.1).
func (t *Tree) Proof(i int) [][]byte { return path(i, t.leaves) }

func path(m int, l [][]byte) [][]byte {
	if len(l) <= 1 {
		return nil
	}
	k := split(len(l))
	if m < k {
		return append(path(m, l[:k]), mth(l[k:]))
	}
	return append(path(m-k, l[k:]), mth(l[:k]))
}

// VerifyInclusion recomputes the root from a leaf's data, index, tree size and audit path.
func VerifyInclusion(data []byte, index, size uint64, proof [][]byte, root []byte) bool {
	if index >= size {
		return false
	}
	fn, sn := index, size-1
	r := leafHash(data)
	for _, p := range proof {
		if sn == 0 {
			return false
		}
		if fn%2 == 1 || fn == sn {
			r = nodeHash(p, r)
			for fn%2 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			r = nodeHash(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	return sn == 0 && string(r) == string(root)
}
