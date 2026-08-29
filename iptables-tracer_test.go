package main

import "testing"

func TestValidNflogGroup(t *testing.T) {
	cases := []struct {
		group int
		valid bool
	}{
		{0, true},
		{22, true},
		{65535, true},
		{-1, false},
		{65536, false},
		{1 << 20, false},
	}
	for _, c := range cases {
		if got := validNflogGroup(c.group); got != c.valid {
			t.Errorf("validNflogGroup(%d) = %v, want %v", c.group, got, c.valid)
		}
	}
}
