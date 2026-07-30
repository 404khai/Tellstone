/*
Package tls
Tellstone TLS Certificate Rotation
File: reloader.go
Description: Watches TLS certificate, private key, and client CA directories and atomically publishes validated replacements for new connections.

Authors:

	Khai
*/
package tls

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Saxy/Tellstone/internal/log"
	"github.com/fsnotify/fsnotify"
)

const certificateReloadDebounce = 500 * time.Millisecond

// Reloader watches the parent directories of configured TLS files. Watching
// directories rather than individual files supports atomic rename workflows and
// Kubernetes Secret projection, where the ..data symlink is replaced on rotation.
type Reloader struct {
	certPath string
	keyPath  string
	caPath   string

	watcher     *fsnotify.Watcher
	closeOnce   sync.Once
	watchedDirs map[string]struct{}
	targets     map[string]struct{}
	configs     *ConfigStore
	fingerprint [sha256.Size]byte
	debounce    time.Duration

	reloadTotal       atomic.Uint64
	reloadErrorsTotal atomic.Uint64
	expiryUnix        atomic.Int64
}

// NewReloader validates the initial TLS material, creates one watch per distinct
// parent directory, and returns a reloader ready to run. The directory watches are
// installed before the initial read so rotation cannot be missed during startup.
func NewReloader(certPath, keyPath, caPath string) (*Reloader, error) {
	certPath, err := absoluteCleanPath(certPath)
	if err != nil {
		return nil, fmt.Errorf("tls: certificate path: %w", err)
	}
	keyPath, err = absoluteCleanPath(keyPath)
	if err != nil {
		return nil, fmt.Errorf("tls: key path: %w", err)
	}
	if caPath != "" {
		caPath, err = absoluteCleanPath(caPath)
		if err != nil {
			return nil, fmt.Errorf("tls: CA path: %w", err)
		}
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("tls: create certificate watcher: %w", err)
	}
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = watcher.Close()
		}
	}()

	dirs := make(map[string]struct{}, 3)
	targets := make(map[string]struct{}, 3)
	for _, path := range []string{certPath, keyPath, caPath} {
		if path == "" {
			continue
		}
		targets[path] = struct{}{}
		dirs[filepath.Dir(path)] = struct{}{}
	}
	for dir := range dirs {
		if err = watcher.Add(dir); err != nil {
			return nil, fmt.Errorf("tls: watch certificate directory %q: %w", dir, err)
		}
	}

	cfg, fingerprint, err := loadConfig(certPath, keyPath, caPath)
	if err != nil {
		return nil, err
	}
	configs, err := NewConfigStore(cfg)
	if err != nil {
		return nil, err
	}
	r := &Reloader{
		certPath:    certPath,
		keyPath:     keyPath,
		caPath:      caPath,
		watcher:     watcher,
		watchedDirs: dirs,
		targets:     targets,
		configs:     configs,
		fingerprint: fingerprint,
		debounce:    certificateReloadDebounce,
	}
	r.expiryUnix.Store(cfg.Certificates[0].Leaf.NotAfter.Unix())
	closeOnError = false
	return r, nil
}

func absoluteCleanPath(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	// Deliberately do not evaluate symlinks: resolving a Kubernetes ..data link
	// would pin the reloader to the old Secret projection directory.
	return filepath.Clean(absolute), nil
}

// Configs returns the shared atomic configuration store used by both listeners.
func (r *Reloader) Configs() *ConfigStore {
	if r == nil {
		return nil
	}
	return r.configs
}

// Close releases the filesystem watcher. It is safe to call after Run exits or
// during startup cleanup before Run begins.
func (r *Reloader) Close() error {
	if r == nil || r.watcher == nil {
		return nil
	}
	var err error
	r.closeOnce.Do(func() { err = r.watcher.Close() })
	return err
}

// Run processes filesystem notifications until ctx is canceled. Invalid replacement
// material is logged and ignored, leaving the last valid configuration active.
func (r *Reloader) Run(ctx context.Context, logger log.Logger) error {
	if r == nil || r.watcher == nil {
		return fmt.Errorf("tls: certificate reloader is not initialized")
	}
	if logger == nil {
		logger = log.NewNoOpLogger()
	}
	defer r.Close()

	var timer *time.Timer
	var timerC <-chan time.Time
	schedule := func() {
		if timer == nil {
			timer = time.NewTimer(r.debounce)
			timerC = timer.C
			return
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(r.debounce)
		timerC = timer.C
	}
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return nil
		case event, ok := <-r.watcher.Events:
			if !ok {
				return errors.New("tls: certificate watcher event channel closed")
			}
			if r.relevantEvent(event.Name) {
				// Direct writes, atomic renames onto a target, and Kubernetes ..data
				// symlink swaps all settle into one complete snapshot reload.
				schedule()
			}
		case watchErr, ok := <-r.watcher.Errors:
			if !ok {
				return errors.New("tls: certificate watcher error channel closed")
			}
			r.reloadErrorsTotal.Add(1)
			if logger.Enabled(log.LevelError) {
				logger.Log(log.LevelError, "tls certificate watcher error",
					log.String("error", watchErr.Error()),
				)
			}
			// A watcher overflow means events may have been lost. Rescan the complete
			// snapshot after the debounce window rather than waiting for another event.
			schedule()
		case <-timerC:
			timerC = nil
			r.reload(logger)
		}
	}
}

func (r *Reloader) relevantEvent(name string) bool {
	name = filepath.Clean(name)
	if _, ok := r.targets[name]; ok {
		return true
	}
	if _, ok := r.watchedDirs[name]; ok {
		return true
	}
	// Kubernetes publishes a projected Secret by atomically renaming ..data_tmp
	// over ..data while the visible certificate paths remain unchanged symlinks.
	base := filepath.Base(name)
	if base != "..data" && base != "..data_tmp" {
		return false
	}
	_, ok := r.watchedDirs[filepath.Dir(name)]
	return ok
}

func (r *Reloader) reload(logger log.Logger) {
	cfg, fingerprint, err := loadConfig(r.certPath, r.keyPath, r.caPath)
	if err != nil {
		r.reloadErrorsTotal.Add(1)
		if logger.Enabled(log.LevelError) {
			logger.Log(log.LevelError, "tls certificate reload failed; retaining current certificate",
				log.String("error", err.Error()),
			)
		}
		return
	}
	if bytes.Equal(fingerprint[:], r.fingerprint[:]) {
		return
	}
	if err = r.configs.Store(cfg); err != nil {
		r.reloadErrorsTotal.Add(1)
		if logger.Enabled(log.LevelError) {
			logger.Log(log.LevelError, "tls certificate reload failed; retaining current certificate",
				log.String("error", err.Error()),
			)
		}
		return
	}

	r.fingerprint = fingerprint
	r.expiryUnix.Store(cfg.Certificates[0].Leaf.NotAfter.Unix())
	r.reloadTotal.Add(1)
	if logger.Enabled(log.LevelInfo) {
		logger.Log(log.LevelInfo, "tls certificate rotated",
			log.String("serial", cfg.Certificates[0].Leaf.SerialNumber.String()),
			log.String("not_after", cfg.Certificates[0].Leaf.NotAfter.UTC().Format(time.RFC3339)),
		)
	}
}

// ReloadTotal returns the number of validated configurations published after startup.
func (r *Reloader) ReloadTotal() uint64 {
	if r == nil {
		return 0
	}
	return r.reloadTotal.Load()
}

// ReloadErrorsTotal returns the number of watcher or validation failures.
func (r *Reloader) ReloadErrorsTotal() uint64 {
	if r == nil {
		return 0
	}
	return r.reloadErrorsTotal.Load()
}

// CertificateExpirySeconds returns the active leaf certificate's NotAfter value
// as Unix epoch seconds for Prometheus exposition.
func (r *Reloader) CertificateExpirySeconds() int64 {
	if r == nil {
		return 0
	}
	return r.expiryUnix.Load()
}
