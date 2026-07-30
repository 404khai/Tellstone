/*
Package tls
Tellstone TLS Certificate Rotation Tests
File: reloader_test.go
Description: Verifies atomic TLS config publication, invalid-reload retention, and Kubernetes Secret projection handling.

Authors:

	Khai
*/
package tls

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Saxy/Tellstone/internal/log"
)

func TestBuildConfigPopulatesLeaf(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "tls.crt")
	keyPath := filepath.Join(dir, "tls.key")
	writeTLSFiles(t, certPath, keyPath, []byte(rsaCertPEM), []byte(rsaKeyPEM))

	cfg, err := BuildConfig(certPath, keyPath, "")
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	if cfg.Certificates[0].Leaf == nil {
		t.Fatal("expected parsed leaf certificate")
	}
	if cfg.MinVersion != VersionTLS13 || cfg.MaxVersion != VersionTLS13 {
		t.Fatalf("expected TLS 1.3 only, got min=%x max=%x", cfg.MinVersion, cfg.MaxVersion)
	}
}

func TestReloaderPublishesValidRotationAndRetainsInvalidReplacement(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "tls.crt")
	keyPath := filepath.Join(dir, "tls.key")
	writeTLSFiles(t, certPath, keyPath, []byte(rsaCertPEM), []byte(rsaKeyPEM))

	r, err := NewReloader(certPath, keyPath, "")
	if err != nil {
		t.Fatalf("NewReloader: %v", err)
	}
	r.debounce = 20 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx, log.NewNoOpLogger()) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Run: %v", err)
		}
	})

	initial := r.Configs().Load()
	writeTLSFiles(t, certPath, keyPath, []byte(ecdsaCertPEM), []byte(ecdsaKeyPEM))
	waitForTLSCondition(t, time.Second, func() bool { return r.ReloadTotal() == 1 })
	rotated := r.Configs().Load()
	if rotated == initial {
		t.Fatal("expected a newly published TLS config")
	}
	if rotated.Certificates[0].Leaf.SerialNumber.Cmp(initial.Certificates[0].Leaf.SerialNumber) == 0 {
		t.Fatal("expected the active leaf certificate to change")
	}

	if err := os.WriteFile(certPath, []byte("not a certificate"), 0o600); err != nil {
		t.Fatalf("write invalid certificate: %v", err)
	}
	waitForTLSCondition(t, time.Second, func() bool { return r.ReloadErrorsTotal() >= 1 })
	if got := r.Configs().Load(); got != rotated {
		t.Fatal("invalid replacement must retain the last valid TLS config")
	}
}

func TestReloaderDoesNotDelayRotationForUnrelatedDirectoryNoise(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "tls.crt")
	keyPath := filepath.Join(dir, "tls.key")
	noisePath := filepath.Join(dir, "application.log")
	writeTLSFiles(t, certPath, keyPath, []byte(rsaCertPEM), []byte(rsaKeyPEM))

	r, err := NewReloader(certPath, keyPath, "")
	if err != nil {
		t.Fatalf("NewReloader: %v", err)
	}
	r.debounce = 40 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx, log.NewNoOpLogger()) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Run: %v", err)
		}
	})

	noiseDone := make(chan struct{})
	go func() {
		defer close(noiseDone)
		for i := 0; i < 40; i++ {
			_ = os.WriteFile(noisePath, []byte(time.Now().String()), 0o600)
			time.Sleep(10 * time.Millisecond)
		}
	}()
	writeTLSFiles(t, certPath, keyPath, []byte(ecdsaCertPEM), []byte(ecdsaKeyPEM))
	waitForTLSCondition(t, 250*time.Millisecond, func() bool { return r.ReloadTotal() == 1 })
	<-noiseDone
}

func TestReloaderPublishesCAOnlyRotation(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "tls.crt")
	keyPath := filepath.Join(dir, "tls.key")
	caPath := filepath.Join(dir, "ca.crt")
	writeTLSFiles(t, certPath, keyPath, []byte(rsaCertPEM), []byte(rsaKeyPEM))
	if err := os.WriteFile(caPath, []byte(rsaCertPEM), 0o600); err != nil {
		t.Fatalf("write initial CA: %v", err)
	}

	r, err := NewReloader(certPath, keyPath, caPath)
	if err != nil {
		t.Fatalf("NewReloader: %v", err)
	}
	r.debounce = 20 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx, log.NewNoOpLogger()) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Run: %v", err)
		}
	})

	initial := r.Configs().Load()
	if err := os.WriteFile(caPath, []byte(ecdsaCertPEM), 0o600); err != nil {
		t.Fatalf("write replacement CA: %v", err)
	}
	waitForTLSCondition(t, time.Second, func() bool { return r.ReloadTotal() == 1 })
	rotated := r.Configs().Load()
	if rotated == initial {
		t.Fatal("expected CA-only rotation to publish a new config")
	}
	if rotated.Certificates[0].Leaf.SerialNumber.Cmp(initial.Certificates[0].Leaf.SerialNumber) != 0 {
		t.Fatal("CA-only rotation must not change the server leaf certificate")
	}
}

func TestReloaderDetectsKubernetesSecretProjectionSwap(t *testing.T) {
	root := t.TempDir()
	writeProjectedSecretVersion(t, root, "..2026_01", []byte(rsaCertPEM), []byte(rsaKeyPEM))
	if err := os.Symlink("..2026_01", filepath.Join(root, "..data")); err != nil {
		t.Fatalf("create ..data symlink: %v", err)
	}
	if err := os.Symlink("..data/tls.crt", filepath.Join(root, "tls.crt")); err != nil {
		t.Fatalf("create certificate symlink: %v", err)
	}
	if err := os.Symlink("..data/tls.key", filepath.Join(root, "tls.key")); err != nil {
		t.Fatalf("create key symlink: %v", err)
	}

	r, err := NewReloader(filepath.Join(root, "tls.crt"), filepath.Join(root, "tls.key"), "")
	if err != nil {
		t.Fatalf("NewReloader: %v", err)
	}
	r.debounce = 20 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx, log.NewNoOpLogger()) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Run: %v", err)
		}
	})

	initial := r.Configs().Load()
	writeProjectedSecretVersion(t, root, "..2026_02", []byte(ecdsaCertPEM), []byte(ecdsaKeyPEM))
	if err := os.Symlink("..2026_02", filepath.Join(root, "..data_tmp")); err != nil {
		t.Fatalf("create replacement ..data symlink: %v", err)
	}
	if err := os.Rename(filepath.Join(root, "..data_tmp"), filepath.Join(root, "..data")); err != nil {
		t.Fatalf("replace ..data symlink: %v", err)
	}

	waitForTLSCondition(t, time.Second, func() bool { return r.ReloadTotal() == 1 })
	if got := r.Configs().Load(); got == initial {
		t.Fatal("expected Kubernetes projection swap to publish a new config")
	}
}

func writeTLSFiles(t *testing.T, certPath, keyPath string, certPEM, keyPEM []byte) {
	t.Helper()
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("write certificate: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
}

func writeProjectedSecretVersion(t *testing.T, root, name string, certPEM, keyPEM []byte) {
	t.Helper()
	dir := filepath.Join(root, name)
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("create projected Secret version: %v", err)
	}
	writeTLSFiles(t, filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key"), certPEM, keyPEM)
}

func waitForTLSCondition(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition was not met before timeout")
}
