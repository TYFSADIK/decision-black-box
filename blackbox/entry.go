// Package blackbox is a tamper-evident audit layer for human-in-the-loop decisions.
//
// Every decision is an Entry. Entries are hash-chained (each commits to the
// previous hash), individually signed with Ed25519, and committed to a Merkle
// tree (RFC 6962 hashing) so a single entry can be proven without the whole log.
//
// Limits: a hash chain proves the log was not edited after the fact. It does not
// prove the log is complete. Publish signed tree heads (checkpoints) to a second
// party, or the operator can truncate and re-sign.
package blackbox

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

type Entry struct {
	Seq      uint64          `json:"seq"`
	Time     time.Time       `json:"time"`
	Actor    string          `json:"actor"`  // operator id or system component
	Action   string          `json:"action"` // e.g. "track.classify", "alert.ack"
	Inputs   json.RawMessage `json:"inputs"` // what the human saw (track ids, confidence...)
	Decision string          `json:"decision"`
	Policy   *PolicyResult   `json:"policy,omitempty"`
	PrevHash string          `json:"prev_hash"`
	Hash     string          `json:"hash"`
	Sig      string          `json:"sig"`
}

type PolicyResult struct {
	Allowed bool     `json:"allowed"`
	Reasons []string `json:"reasons,omitempty"`
	Bundle  string   `json:"bundle"` // policy version/digest used, so replay can re-evaluate
}

// canonical returns the bytes that are hashed: the entry without Hash and Sig.
func (e Entry) canonical() ([]byte, error) {
	c := e
	c.Hash, c.Sig = "", ""
	c.Time = c.Time.UTC().Round(time.Microsecond)
	return json.Marshal(c)
}

func (e *Entry) seal(priv ed25519.PrivateKey) error {
	b, err := e.canonical()
	if err != nil {
		return err
	}
	sum := sha256.Sum256(b)
	e.Hash = hex.EncodeToString(sum[:])
	e.Sig = hex.EncodeToString(ed25519.Sign(priv, sum[:]))
	return nil
}

var (
	ErrHash  = errors.New("entry hash mismatch")
	ErrSig   = errors.New("entry signature invalid")
	ErrChain = errors.New("hash chain broken")
	ErrSeq   = errors.New("sequence gap")
)

func (e Entry) Verify(pub ed25519.PublicKey) error {
	b, err := e.canonical()
	if err != nil {
		return err
	}
	sum := sha256.Sum256(b)
	if hex.EncodeToString(sum[:]) != e.Hash {
		return ErrHash
	}
	sig, err := hex.DecodeString(e.Sig)
	if err != nil || !ed25519.Verify(pub, sum[:], sig) {
		return ErrSig
	}
	return nil
}
