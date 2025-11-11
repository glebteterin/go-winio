//go:build windows

package winio

import (
	"testing"
)

func TestLxSymlinkRoundTrip(t *testing.T) {
	// Test LX symlink encode/decode
	original := &ReparsePoint{
		Target:       "/usr/bin/bash",
		IsMountPoint: false,
		IsLxSymlink:  true,
	}

	// Encode
	encoded := EncodeReparsePoint(original)

	// Decode
	decoded, err := DecodeReparsePoint(encoded)
	if err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}

	// Verify
	if decoded.Target != original.Target {
		t.Errorf("Target mismatch: got %q, want %q", decoded.Target, original.Target)
	}
	if decoded.IsLxSymlink != original.IsLxSymlink {
		t.Errorf("IsLxSymlink mismatch: got %v, want %v", decoded.IsLxSymlink, original.IsLxSymlink)
	}
	if decoded.IsMountPoint != original.IsMountPoint {
		t.Errorf("IsMountPoint mismatch: got %v, want %v", decoded.IsMountPoint, original.IsMountPoint)
	}
}

func TestWindowsSymlinkNotLx(t *testing.T) {
	// Test that regular Windows symlinks are not marked as LX
	original := &ReparsePoint{
		Target:       `C:\Windows\System32`,
		IsMountPoint: false,
		IsLxSymlink:  false,
	}

	// Encode
	encoded := EncodeReparsePoint(original)

	// Decode
	decoded, err := DecodeReparsePoint(encoded)
	if err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}

	// Verify it's NOT an LX symlink
	if decoded.IsLxSymlink {
		t.Errorf("Windows symlink incorrectly marked as LX symlink")
	}
}
