package blackbox

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newLog(t *testing.T) (*Log, string, ed25519.PublicKey) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	p := filepath.Join(t.TempDir(), "bb.jsonl")
	l, err := Open(p, priv)
	if err != nil {
		t.Fatal(err)
	}
	return l, p, pub
}

func TestChainVerifies(t *testing.T) {
	l, p, pub := newLog(t)
	for i := 0; i < 5; i++ {
		if _, err := l.Append("op1", "alert.ack", map[string]int{"track": i}, "ack", nil); err != nil {
			t.Fatal(err)
		}
	}
	l.Close()
	es, _ := ReadAll(p)
	if i, err := VerifyChain(es, pub); err != nil {
		t.Fatalf("entry %d: %v", i, err)
	}
}

func TestTamperDetected(t *testing.T) {
	l, p, pub := newLog(t)
	l.Append("op1", "track.classify", map[string]any{"track": 7}, "hostile", nil)
	l.Append("op1", "alert.ack", nil, "ack", nil)
	l.Close()
	b, _ := os.ReadFile(p)
	os.WriteFile(p, []byte(strings.Replace(string(b), "hostile", "neutral", 1)), 0o600)
	es, _ := ReadAll(p)
	if i, err := VerifyChain(es, pub); err != ErrHash || i != 0 {
		t.Fatalf("want ErrHash at 0, got %v at %d", err, i)
	}
	// Deleting an entry breaks the chain / sequence.
	if _, err := VerifyChain(es[1:], pub); err == nil {
		t.Fatal("deletion not detected")
	}
}

func TestMerkleInclusion(t *testing.T) {
	for _, n := range []int{1, 2, 3, 7, 8, 13} {
		tr := &Tree{}
		var data [][]byte
		for i := 0; i < n; i++ {
			d := []byte{byte(i), 0xAB}
			data = append(data, d)
			tr.Append(d)
		}
		root := tr.Root()
		for i := 0; i < n; i++ {
			if !VerifyInclusion(data[i], uint64(i), uint64(n), tr.Proof(i), root) {
				t.Fatalf("n=%d i=%d proof failed", n, i)
			}
		}
		if n > 1 && VerifyInclusion([]byte("forged"), 0, uint64(n), tr.Proof(0), root) {
			t.Fatal("forged leaf accepted")
		}
	}
}

func TestCheckpoint(t *testing.T) {
	l, _, pub := newLog(t)
	l.Append("op1", "alert.ack", nil, "ack", nil)
	c := l.Checkpoint()
	if !VerifyCheckpoint(c, pub) {
		t.Fatal("checkpoint invalid")
	}
	c.Size++
	if VerifyCheckpoint(c, pub) {
		t.Fatal("altered checkpoint accepted")
	}
}

func TestOPAFailClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"result": map[string]any{"allow": false, "deny": []string{"needs second operator"}}})
	}))
	defer srv.Close()
	res, err := OPA{URL: srv.URL, Bundle: "v1"}.Evaluate(context.Background(), map[string]string{"action": "asset.task"})
	if err != nil || res.Allowed || len(res.Reasons) != 1 {
		t.Fatalf("unexpected %+v %v", res, err)
	}
	res, err = OPA{URL: "http://127.0.0.1:1"}.Evaluate(context.Background(), nil)
	if err == nil || res.Allowed {
		t.Fatal("unreachable OPA must fail closed")
	}
}
