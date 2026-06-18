package predictconfidence

import "math"

// PredictAndConfidence returns the predicted class and confidence for a score vector.
// It supports already-normalized probabilities, vote counts, and raw score vectors.
func PredictAndConfidence(scores []float64) (int, float64) {
	n := len(scores)
	if n == 0 {
		return 0, 0.0
	}

	var sum float64
	for _, v := range scores {
		sum += v
	}
	const eps = 1e-6

	var probs []float64
	if math.Abs(sum-1.0) < eps && sum > 0 {
		probs = make([]float64, n)
		copy(probs, scores)
	} else {
		allNonNeg := true
		for _, v := range scores {
			if v < 0 {
				allNonNeg = false
				break
			}
		}
		if allNonNeg && sum > 0 {
			probs = make([]float64, n)
			for i, v := range scores {
				probs[i] = v / sum
			}
		} else {
			max := scores[0]
			for _, v := range scores {
				if v > max {
					max = v
				}
			}
			exps := make([]float64, n)
			var expSum float64
			for i, v := range scores {
				e := math.Exp(v - max)
				exps[i] = e
				expSum += e
			}
			probs = make([]float64, n)
			for i := range exps {
				probs[i] = exps[i] / expSum
			}
		}
	}

	bestIdx := 0
	bestVal := probs[0]
	for i, p := range probs {
		if p > bestVal {
			bestVal = p
			bestIdx = i
		}
	}

	return bestIdx, bestVal
}
