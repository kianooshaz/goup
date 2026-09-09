package security

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// CacheTTL is how long a cached vulnerability result stays fresh. Security
// data changes slowly (advisories take days to publish), so one day is a
// reasonable balance between responsiveness and freshness.
const CacheTTL = 24 * time.Hour

// cacheEntry is the persisted form of one Check result.
type cacheEntry struct {
	FetchedAt time.Time       `json:"fetched_at"`
	Vulns     []Vulnerability `json:"vulns"`
}

// DiskCache caches Check results on disk, keyed by module@version.
// A cached hit is an optimization, not a source of truth: callers still get
// a Checked=true status, and the entry carries its fetch time so a future
// "as of" indication is possible.
type DiskCache struct {
	dir string
	ttl time.Duration
}

// NewDiskCache creates a cache rooted at dir (created on demand). When dir
// is empty the cache is disabled (all operations are no-ops).
func NewDiskCache(dir string) *DiskCache {
	return &DiskCache{dir: dir, ttl: CacheTTL}
}

// NewDiskCacheWithTTL creates a cache with a custom TTL (used in tests).
func NewDiskCacheWithTTL(dir string, ttl time.Duration) *DiskCache {
	return &DiskCache{dir: dir, ttl: ttl}
}

// key returns the cache file path for a module@version pair.
func (c *DiskCache) key(module, version string) string {
	sum := sha256.Sum256([]byte(module + "@" + version))
	return filepath.Join(c.dir, hex.EncodeToString(sum[:16])+".json")
}

// Get returns the cached vulnerabilities for module@version if a fresh
// entry exists. Missing, expired, or corrupt entries return ok=false and
// are treated as a miss; corrupt entries are removed.
func (c *DiskCache) Get(module, version string) ([]Vulnerability, bool) {
	if c == nil || c.dir == "" {
		return nil, false
	}
	data, err := os.ReadFile(c.key(module, version))
	if err != nil {
		return nil, false
	}
	var entry cacheEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		_ = os.Remove(c.key(module, version))
		return nil, false
	}
	if time.Since(entry.FetchedAt) > c.ttl {
		return nil, false
	}
	return entry.Vulns, true
}

// Put stores a Check result. Errors are ignored: the cache is best-effort
// and must never break the security check itself.
func (c *DiskCache) Put(module, version string, vulns []Vulnerability) {
	if c == nil || c.dir == "" {
		return
	}
	if err := os.MkdirAll(c.dir, 0o700); err != nil {
		return
	}
	data, err := json.Marshal(cacheEntry{
		FetchedAt: time.Now(),
		Vulns:     vulns,
	})
	if err != nil {
		return
	}
	path := c.key(module, version)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return
	}
	// Atomic rename prevents readers from seeing partial writes.
	_ = os.Rename(tmp, path)
}

// DefaultCachePath returns the default cache directory for goup.
func DefaultCachePath() string {
	base, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	return filepath.Join(base, "goup", "vulndb")
}

// String renders the cache location for diagnostics.
func (c *DiskCache) String() string {
	if c == nil || c.dir == "" {
		return "disabled"
	}
	return fmt.Sprintf("dir=%s ttl=%s", c.dir, c.ttl)
}
