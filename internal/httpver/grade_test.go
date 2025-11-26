package httpver

import "testing"

func TestComputeMinimalGrade(t *testing.T) {
	tests := []struct {
		name       string
		hasH3      bool
		hasH2      bool
		tlsVersion string
		wantGrade  string
	}{
		{
			name:       "http3 wins",
			hasH3:      true,
			hasH2:      true,
			tlsVersion: "TLS 1.3",
			wantGrade:  "A",
		},
		{
			name:       "h2 tls13",
			hasH3:      false,
			hasH2:      true,
			tlsVersion: "TLS 1.3",
			wantGrade:  "B",
		},
		{
			name:       "h2 tls12",
			hasH3:      false,
			hasH2:      true,
			tlsVersion: "TLS 1.2",
			wantGrade:  "C",
		},
		{
			name:       "h2 unknown tls treated as C",
			hasH3:      false,
			hasH2:      true,
			tlsVersion: "",
			wantGrade:  "C",
		},
		{
			name:       "no h2 h3",
			hasH3:      false,
			hasH2:      false,
			tlsVersion: "",
			wantGrade:  "F",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, grade := computeMinimalGrade(tt.hasH3, tt.hasH2, tt.tlsVersion)
			if grade != tt.wantGrade {
				t.Fatalf("got grade %q, want %q", grade, tt.wantGrade)
			}
		})
	}
}


