// Package config reads runtime settings from environment variables. None of
// them is a secret: every key in this service is per Secret or random at start.
package config

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
)

// MaxContentBytes is the largest Secret content accepted.
const MaxContentBytes = 64 << 10

// Config holds all runtime settings.
type Config struct {
	ListenAddr    string
	RedisAddr     string
	PublicBaseURL string
	CreatePerSec  float64
	CreateBurst   int
	ReadPerSec    float64
	ReadBurst     int
	// Passphrase-bearing reads, each of which costs one Argon2id.
	UnlockPerSec float64
	UnlockBurst  int
	// Bytes of Secret content one client may store.
	CreateBytesPerSec float64
	CreateBytesBurst  int
	ArgonTime         uint32
	ArgonMemoryKiB    uint32
}

// Load reads Config from the environment, applying defaults.
func Load() (Config, error) {
	c := Config{
		ListenAddr:    env("LISTEN_ADDR", ":8080"),
		RedisAddr:     env("REDIS_ADDR", "redis:6379"),
		PublicBaseURL: strings.TrimRight(env("PUBLIC_BASE_URL", "http://localhost:8080"), "/"),
	}
	var err error
	if c.CreatePerSec, err = envFloat("RATE_CREATE_PER_SEC", 10); err != nil {
		return c, err
	}
	if c.CreateBurst, err = envInt("RATE_CREATE_BURST", 20); err != nil {
		return c, err
	}
	if c.ReadPerSec, err = envFloat("RATE_READ_PER_SEC", 100); err != nil {
		return c, err
	}
	if c.ReadBurst, err = envInt("RATE_READ_BURST", 100); err != nil {
		return c, err
	}
	if c.UnlockPerSec, err = envFloat("RATE_UNLOCK_PER_SEC", 20); err != nil {
		return c, err
	}
	if c.UnlockBurst, err = envInt("RATE_UNLOCK_BURST", 40); err != nil {
		return c, err
	}
	// Default byte budget follows the create rate (4 KiB per allowed create),
	// so raising RATE_CREATE_PER_SEC for a load test raises it too.
	if c.CreateBytesPerSec, err = envFloat("RATE_CREATE_BYTES_PER_SEC", c.CreatePerSec*4096); err != nil {
		return c, err
	}
	if c.CreateBytesBurst, err = envInt("RATE_CREATE_BYTES_BURST", 1<<20); err != nil {
		return c, err
	}
	if c.CreateBytesPerSec > 0 && c.CreateBytesBurst < MaxContentBytes {
		return c, fmt.Errorf("config: RATE_CREATE_BYTES_BURST must be >= %d, the largest Secret", MaxContentBytes)
	}
	if c.ArgonTime, err = envUint32("KDF_ARGON_TIME", 2); err != nil {
		return c, err
	}
	if c.ArgonMemoryKiB, err = envUint32("KDF_ARGON_MEMORY_KIB", 19*1024); err != nil {
		return c, err
	}
	if c.ArgonTime < 1 || c.ArgonMemoryKiB < 8*1024 {
		return c, fmt.Errorf("config: KDF_ARGON_TIME must be >= 1 and KDF_ARGON_MEMORY_KIB >= 8192")
	}
	u, err := url.Parse(c.PublicBaseURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return c, fmt.Errorf("config: PUBLIC_BASE_URL must be an absolute http(s) URL")
	}
	return c, nil
}

func env(k, def string) string {
	if v, ok := os.LookupEnv(k); ok && v != "" {
		return v
	}
	return def
}

func envInt(k string, def int) (int, error) {
	v := env(k, "")
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("config: %s: %w", k, err)
	}
	return n, nil
}

func envUint32(k string, def uint32) (uint32, error) {
	v := env(k, "")
	if v == "" {
		return def, nil
	}
	n, err := strconv.ParseUint(v, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("config: %s: %w", k, err)
	}
	return uint32(n), nil
}

func envFloat(k string, def float64) (float64, error) {
	v := env(k, "")
	if v == "" {
		return def, nil
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return 0, fmt.Errorf("config: %s: %w", k, err)
	}
	return f, nil
}
