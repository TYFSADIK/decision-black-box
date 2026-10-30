package blackbox

import (
	"bufio"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

const genesis = "0000000000000000000000000000000000000000000000000000000000000000"

// Log is an append-only JSONL file. Each append is fsynced before returning.
type Log struct {
	mu   sync.Mutex
	f    *os.File
	priv ed25519.PrivateKey
	seq  uint64
	prev string
	tree *Tree
}

func Open(path string, priv ed25519.PrivateKey) (*Log, error) {
	l := &Log{priv: priv, prev: genesis, tree: &Tree{}}
	if entries, err := ReadAll(path); err == nil {
		for _, e := range entries {
			l.seq, l.prev = e.Seq, e.Hash
			l.tree.Append(mustHex(e.Hash))
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, err
	}
	l.f = f
	return l, nil
}

func (l *Log) Close() error { return l.f.Close() }

func (l *Log) Append(actor, action string, inputs any, decision string, pol *PolicyResult) (Entry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	raw, err := json.Marshal(inputs)
	if err != nil {
		return Entry{}, err
	}
	e := Entry{Seq: l.seq + 1, Time: time.Now().UTC(), Actor: actor, Action: action,
		Inputs: raw, Decision: decision, Policy: pol, PrevHash: l.prev}
	if err := e.seal(l.priv); err != nil {
		return Entry{}, err
	}
	line, _ := json.Marshal(e)
	if _, err := l.f.Write(append(line, '\n')); err != nil {
		return Entry{}, err
	}
	if err := l.f.Sync(); err != nil {
		return Entry{}, err
	}
	l.seq, l.prev = e.Seq, e.Hash
	l.tree.Append(mustHex(e.Hash))
	return e, nil
}

// Checkpoint is a signed tree head: hand it to a second party to make truncation detectable.
type Checkpoint struct {
	Size uint64 `json:"size"`
	Root string `json:"root"`
	Sig  string `json:"sig"`
}

func (l *Log) Checkpoint() Checkpoint {
	l.mu.Lock()
	defer l.mu.Unlock()
	root := l.tree.Root()
	msg := fmt.Sprintf("blackbox-checkpoint\n%d\n%x\n", l.tree.Size(), root)
	return Checkpoint{l.tree.Size(), hex.EncodeToString(root), hex.EncodeToString(ed25519.Sign(l.priv, []byte(msg)))}
}

func VerifyCheckpoint(c Checkpoint, pub ed25519.PublicKey) bool {
	sig, err := hex.DecodeString(c.Sig)
	return err == nil && ed25519.Verify(pub, []byte(fmt.Sprintf("blackbox-checkpoint\n%d\n%s\n", c.Size, c.Root)), sig)
}

func ReadAll(path string) ([]Entry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Entry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	for sc.Scan() {
		if strings.TrimSpace(sc.Text()) == "" {
			continue
		}
		var e Entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			return nil, fmt.Errorf("line %d: %w", len(out)+1, err)
		}
		out = append(out, e)
	}
	return out, sc.Err()
}

// VerifyChain checks every signature, every hash, the chain links, and sequence continuity.
// It returns the index of the first bad entry (or -1) and the error.
func VerifyChain(entries []Entry, pub ed25519.PublicKey) (int, error) {
	prev := genesis
	for i, e := range entries {
		if e.Seq != uint64(i+1) {
			return i, ErrSeq
		}
		if e.PrevHash != prev {
			return i, ErrChain
		}
		if err := e.Verify(pub); err != nil {
			return i, err
		}
		prev = e.Hash
	}
	return -1, nil
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
