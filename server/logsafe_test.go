package server

import "testing"

func TestLogSafeStripsControlChars(t *testing.T) {
	if got := logSafe("a\r\nINFO forged\tx\x1b[0m"); got != "a__INFO forged_x_[0m" {
		t.Errorf("got %q", got)
	}
	if logSafe("tenant-acme") != "tenant-acme" {
		t.Error("plain values must be unchanged")
	}
}
