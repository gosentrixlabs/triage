package priority

import (
	"testing"

	"github.com/gosentrixlabs/triage/internal/input"
)

func ptr(b bool) *bool { return &b }

func TestEvaluate(t *testing.T) {
	cases := []struct {
		name  string
		item  input.Item
		score int
		band  string
	}{
		{"every signal raised", input.Item{Severity: "critical", KnownExploited: ptr(true), Exposure: "internet", AssetCriticality: "high"}, 105, "P1"},
		{"critical and exploited but isolated", input.Item{Severity: "critical", KnownExploited: ptr(true), Exposure: "isolated"}, 70, "P1"},
		{"critical alone", input.Item{Severity: "critical"}, 50, "P2"},
		{"high and internet-facing", input.Item{Severity: "high", Exposure: "internet"}, 50, "P2"},
		{"medium, exploited, low criticality", input.Item{Severity: "medium", KnownExploited: ptr(true), AssetCriticality: "low"}, 45, "P2"},
		{"high alone", input.Item{Severity: "high"}, 35, "P3"},
		{"medium alone", input.Item{Severity: "medium"}, 20, "P3"},
		{"low alone", input.Item{Severity: "low"}, 10, "P4"},
		{"not exploited adds nothing", input.Item{Severity: "low", KnownExploited: ptr(false)}, 10, "P4"},
		{"unknown values add nothing", input.Item{Severity: "medium", Exposure: "unknown", AssetCriticality: "unknown"}, 20, "P3"},
		{"info, isolated, low criticality", input.Item{Severity: "info", Exposure: "isolated", AssetCriticality: "low"}, -15, "P4"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := Evaluate(c.item)
			if res.Score != c.score || res.Band != c.band {
				t.Errorf("got %s/%d, want %s/%d", res.Band, res.Score, c.band, c.score)
			}
		})
	}
}

func TestEveryRuleExplainsItself(t *testing.T) {
	res := Evaluate(input.Item{Severity: "high", Exposure: "internal"})
	want := []string{"severity", "known-exploited", "exposure", "asset-criticality"}
	if len(res.Factors) != len(want) {
		t.Fatalf("got %d factors, want %d", len(res.Factors), len(want))
	}
	sum := 0
	for i, f := range res.Factors {
		if f.Rule != want[i] {
			t.Errorf("factor %d is %q, want %q", i, f.Rule, want[i])
		}
		if f.Reason == "" {
			t.Errorf("factor %q has no reason", f.Rule)
		}
		sum += f.Points
	}
	if sum != res.Score {
		t.Errorf("factors add up to %d but the score is %d", sum, res.Score)
	}
}

func TestBandThresholds(t *testing.T) {
	cases := map[int]string{200: "P1", 70: "P1", 69: "P2", 45: "P2", 44: "P3", 20: "P3", 19: "P4", 0: "P4", -20: "P4"}
	for score, want := range cases {
		if got := band(score); got != want {
			t.Errorf("band(%d) = %s, want %s", score, got, want)
		}
	}
}
