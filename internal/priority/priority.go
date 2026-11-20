// Package priority scores items with a fixed set of explicit rules.
//
// Every rule always contributes one factor, including zero-point factors, so
// an explanation accounts for every input the score depends on. The score is
// the sum of the factors' points. The rules are documented in
// docs/prioritization.md; keep that file in step with this one.
package priority

import (
	"fmt"

	"github.com/gosentrixlabs/triage/internal/input"
)

// Factor is one rule's contribution to a score.
type Factor struct {
	Rule   string `json:"rule"`
	Points int    `json:"points"`
	Reason string `json:"reason"`
}

// Result is an item's priority and the factors behind it.
type Result struct {
	Band    string   `json:"band"`
	Score   int      `json:"score"`
	Factors []Factor `json:"factors"`
}

// Band thresholds: a score at or above Min gets the band.
var Bands = []struct {
	Name string
	Min  int
}{
	{"P1", 70},
	{"P2", 45},
	{"P3", 20},
}

// LowestBand applies when a score is below every threshold in Bands.
const LowestBand = "P4"

// BandSummary describes the thresholds in one line.
const BandSummary = "P1 is 70 or more, P2 is 45 to 69, P3 is 20 to 44, P4 is below 20."

type rule struct {
	name string
	eval func(input.Item) (int, string)
}

var rules = []rule{
	{"severity", severity},
	{"known-exploited", knownExploited},
	{"exposure", exposure},
	{"asset-criticality", assetCriticality},
}

// Evaluate scores an item.
func Evaluate(it input.Item) Result {
	res := Result{Factors: make([]Factor, 0, len(rules))}
	for _, r := range rules {
		points, reason := r.eval(it)
		res.Factors = append(res.Factors, Factor{Rule: r.name, Points: points, Reason: reason})
		res.Score += points
	}
	res.Band = band(res.Score)
	return res
}

func band(score int) string {
	for _, b := range Bands {
		if score >= b.Min {
			return b.Name
		}
	}
	return LowestBand
}

func severity(it input.Item) (int, string) {
	points := map[string]int{"critical": 50, "high": 35, "medium": 20, "low": 10, "info": 0}
	return points[it.Severity], fmt.Sprintf("Severity is %s", it.Severity)
}

func knownExploited(it input.Item) (int, string) {
	switch {
	case it.KnownExploited == nil:
		return 0, "Input does not say whether this is known to be exploited"
	case *it.KnownExploited:
		return 30, "Input marks this as known to be exploited"
	default:
		return 0, "Input marks this as not known to be exploited"
	}
}

func exposure(it input.Item) (int, string) {
	switch it.Exposure {
	case "internet":
		return 15, "Reachable from the internet"
	case "internal":
		return 0, "Reachable only from internal networks"
	case "isolated":
		return -10, "Not reachable over a network"
	case "unknown":
		return 0, "Exposure is marked unknown"
	default:
		return 0, "Exposure not given"
	}
}

func assetCriticality(it input.Item) (int, string) {
	switch it.AssetCriticality {
	case "high":
		return 10, "Asset criticality is high"
	case "medium":
		return 0, "Asset criticality is medium"
	case "low":
		return -5, "Asset criticality is low"
	case "unknown":
		return 0, "Asset criticality is marked unknown"
	default:
		return 0, "Asset criticality not given"
	}
}
