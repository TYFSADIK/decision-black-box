// blackbox: CLI for the decision audit log.
//
//	blackbox keygen  -key keys/bb.key                      (writes bb.key + bb.pub)
//	blackbox append  -key keys/bb.key -log bb.jsonl -actor op1 -action alert.ack -decision ack -inputs '{"track":7}'
//	blackbox verify  -pub keys/bb.pub -log bb.jsonl
//	blackbox prove   -log bb.jsonl -seq 3
//	blackbox replay  -log bb.jsonl [-actor op1]
//	blackbox checkpoint -key keys/bb.key -log bb.jsonl
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/TYFSADIK/decision-black-box/blackbox"
)

func die(f string, a ...any) { fmt.Fprintf(os.Stderr, f+"\n", a...); os.Exit(1) }

func readKey(path string) []byte {
	b, err := os.ReadFile(path)
	if err != nil {
		die("read key: %v", err)
	}
	k, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		die("decode key: %v", err)
	}
	return k
}

func main() {
	if len(os.Args) < 2 {
		die("usage: blackbox keygen|append|verify|prove|replay|checkpoint [flags]")
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	key := fs.String("key", "keys/bb.key", "private key (hex)")
	pubp := fs.String("pub", "keys/bb.pub", "public key (hex)")
	logp := fs.String("log", "blackbox.jsonl", "log file")
	actor := fs.String("actor", "", "actor")
	action := fs.String("action", "", "action")
	decision := fs.String("decision", "", "decision")
	inputs := fs.String("inputs", "null", "inputs JSON")
	seq := fs.Int("seq", 1, "entry sequence number")
	fs.Parse(os.Args[2:])

	switch os.Args[1] {
	case "keygen":
		pub, priv, _ := ed25519.GenerateKey(nil)
		os.MkdirAll(filepath.Dir(*key), 0o700)
		os.WriteFile(*key, []byte(hex.EncodeToString(priv)), 0o600)
		os.WriteFile(strings.TrimSuffix(*key, ".key")+".pub", []byte(hex.EncodeToString(pub)), 0o644)
		fmt.Println("wrote", *key)
	case "append":
		l, err := blackbox.Open(*logp, ed25519.PrivateKey(readKey(*key)))
		if err != nil {
			die("%v", err)
		}
		defer l.Close()
		e, err := l.Append(*actor, *action, json.RawMessage(*inputs), *decision, nil)
		if err != nil {
			die("%v", err)
		}
		fmt.Printf("seq=%d hash=%s\n", e.Seq, e.Hash)
	case "verify":
		es, err := blackbox.ReadAll(*logp)
		if err != nil {
			die("%v", err)
		}
		if i, err := blackbox.VerifyChain(es, ed25519.PublicKey(readKey(*pubp))); err != nil {
			die("FAIL at entry index %d: %v", i, err)
		}
		fmt.Printf("OK: %d entries, chain and signatures valid\n", len(es))
	case "prove":
		es, err := blackbox.ReadAll(*logp)
		if err != nil || *seq < 1 || *seq > len(es) {
			die("bad log or seq")
		}
		t := &blackbox.Tree{}
		for _, e := range es {
			h, _ := hex.DecodeString(e.Hash)
			t.Append(h)
		}
		var p []string
		for _, h := range t.Proof(*seq - 1) {
			p = append(p, hex.EncodeToString(h))
		}
		json.NewEncoder(os.Stdout).Encode(map[string]any{"seq": *seq, "leaf": es[*seq-1].Hash,
			"size": t.Size(), "root": hex.EncodeToString(t.Root()), "proof": p})
	case "replay":
		es, err := blackbox.ReadAll(*logp)
		if err != nil {
			die("%v", err)
		}
		for _, e := range es {
			if *actor == "" || e.Actor == *actor {
				fmt.Printf("%4d %s %-8s %-24s %-10s %s\n", e.Seq, e.Time.Format("2006-01-02T15:04:05Z"), e.Actor, e.Action, e.Decision, e.Inputs)
			}
		}
	case "checkpoint":
		l, err := blackbox.Open(*logp, ed25519.PrivateKey(readKey(*key)))
		if err != nil {
			die("%v", err)
		}
		json.NewEncoder(os.Stdout).Encode(l.Checkpoint())
	default:
		die("unknown command %q", os.Args[1])
	}
}
