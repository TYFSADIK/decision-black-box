package blackbox

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// OPA asks an Open Policy Agent server whether an action is allowed BEFORE it is executed.
// Run: opa run --server --addr :8181 policy/
type OPA struct {
	URL    string // e.g. http://127.0.0.1:8181/v1/data/blackbox/decision
	Bundle string // policy version recorded in every entry
	Client *http.Client
}

func (o OPA) Evaluate(ctx context.Context, input any) (*PolicyResult, error) {
	body, _ := json.Marshal(map[string]any{"input": input})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, o.URL, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	c := o.Client
	if c == nil {
		c = &http.Client{Timeout: 2 * time.Second}
	}
	resp, err := c.Do(req)
	if err != nil {
		// Fail closed: no policy answer means not allowed.
		return &PolicyResult{Allowed: false, Reasons: []string{"policy engine unreachable"}, Bundle: o.Bundle}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return &PolicyResult{Allowed: false, Reasons: []string{fmt.Sprintf("opa http %d", resp.StatusCode)}, Bundle: o.Bundle}, nil
	}
	var out struct {
		Result struct {
			Allow   bool     `json:"allow"`
			Reasons []string `json:"deny"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return &PolicyResult{Allowed: false, Reasons: []string{"bad opa response"}, Bundle: o.Bundle}, err
	}
	return &PolicyResult{Allowed: out.Result.Allow, Reasons: out.Result.Reasons, Bundle: o.Bundle}, nil
}
