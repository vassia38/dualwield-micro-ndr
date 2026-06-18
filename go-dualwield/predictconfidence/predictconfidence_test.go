package predictconfidence

import "testing"

func TestPredictAndConfidence(t *testing.T) {
	tests := []struct {
		name     string
		scores   []float64
		wantIdx  int
		wantConf float64
	}{
		{
			name:     "already probabilities",
			scores:   []float64{0.05, 0.9, 0.05},
			wantIdx:  1,
			wantConf: 0.9,
		},
		{
			name:     "vote counts",
			scores:   []float64{3, 7, 0},
			wantIdx:  1,
			wantConf: 0.7,
		},
		{
			name:     "nonnegative scores normalize to probabilities",
			scores:   []float64{1.0, 2.0, 0.0},
			wantIdx:  1,
			wantConf: 0.66666667,
		},
		{
			name:     "empty scores",
			scores:   []float64{},
			wantIdx:  0,
			wantConf: 0.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idx, conf := PredictAndConfidence(tt.scores)
			if idx != tt.wantIdx {
				t.Fatalf("got idx %d, want %d", idx, tt.wantIdx)
			}
			if tt.name != "empty scores" {
				diff := conf - tt.wantConf
				if diff < 0 {
					diff = -diff
				}
				if diff > 1e-6 {
					t.Fatalf("got conf %.8f, want %.8f", conf, tt.wantConf)
				}
			} else if conf != tt.wantConf {
				t.Fatalf("got conf %.8f, want %.8f", conf, tt.wantConf)
			}
		})
	}
}
