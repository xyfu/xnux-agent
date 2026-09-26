package collect

import "math"

func round(v float64, decimals int) float64 {
	p := math.Pow10(decimals)
	return math.Round(v*p) / p
}

// pct rounds to 1 decimal and clamps to [0, 100].
func pct(v float64) float64 {
	return round(math.Min(100, math.Max(0, v)), 1)
}
