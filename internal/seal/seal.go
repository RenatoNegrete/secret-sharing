// Package seal encrypts and decrypts Secret content (ADR 0001).
//
// encryption key = HKDF-SHA256(SecretKey [‖ Argon2id(Passphrase, salt)], salt, info)
// ciphertext     = AES-256-GCM(key, nonce, content, AAD = LookupID)
//
// No passphrase verifier exists: a wrong Passphrase (or a tampered Secret Key)
// surfaces as ErrAuth from the GCM tag check.
package seal

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"runtime"
	"time"

	"golang.org/x/crypto/argon2"
)

const (
	saltLen  = 16
	keyLen   = 32
	infoKey  = "ots/v1/enc"
	infoPass = "ots/v1/enc+passphrase"
)

// ErrAuth means the ciphertext did not authenticate under the derived key.
var ErrAuth = errors.New("seal: authentication failed")

// Params are the Argon2id cost settings used whenever a Passphrase is involved.
type Params struct {
	ArgonTime      uint32
	ArgonMemoryKiB uint32
}

// Sealed is everything storage keeps for one Secret's content.
type Sealed struct {
	Ciphertext []byte
	Nonce      []byte
	Salt       []byte
}

// Sealer performs sealing and opening. Argon2id runs behind a semaphore sized
// to the CPU count so bursts queue instead of thrashing the CPU.
type Sealer struct {
	params    Params
	sem       chan struct{}
	onWait    func(time.Duration)
	dummySalt []byte
	dummyKey  []byte
	dummy     Sealed
}

// New returns a Sealer. onWait, if non-nil, observes the semaphore wait before each Argon2id run.
func New(p Params, onWait func(time.Duration)) (*Sealer, error) {
	s := &Sealer{
		params:    p,
		sem:       make(chan struct{}, runtime.NumCPU()),
		onWait:    onWait,
		dummySalt: randBytes(saltLen),
		dummyKey:  randBytes(keyLen),
	}
	sealed, err := s.seal(context.Background(), []byte("decoy-content-for-timing"), s.dummyKey, randBytes(16), nil)
	if err != nil {
		return nil, fmt.Errorf("seal: build decoy: %w", err)
	}
	s.dummy = sealed
	return s, nil
}

// Seal encrypts content for a Secret. passphrase may be nil.
func (s *Sealer) Seal(ctx context.Context, content, secretKey, lookupID, passphrase []byte) (Sealed, error) {
	return s.seal(ctx, content, secretKey, lookupID, passphrase)
}

func (s *Sealer) seal(ctx context.Context, content, secretKey, lookupID, passphrase []byte) (Sealed, error) {
	salt := randBytes(saltLen)
	aead, err := s.aead(ctx, secretKey, salt, passphrase)
	if err != nil {
		return Sealed{}, err
	}
	nonce := randBytes(aead.NonceSize())
	return Sealed{Ciphertext: aead.Seal(nil, nonce, content, lookupID), Nonce: nonce, Salt: salt}, nil
}

// Open decrypts a Secret. passphrase must be non-nil exactly when the Secret
// was sealed with one. Returns ErrAuth on any authentication failure.
func (s *Sealer) Open(ctx context.Context, sealed Sealed, secretKey, lookupID, passphrase []byte) ([]byte, error) {
	aead, err := s.aead(ctx, secretKey, sealed.Salt, passphrase)
	if err != nil {
		return nil, err
	}
	if len(sealed.Nonce) != aead.NonceSize() {
		return nil, ErrAuth
	}
	pt, err := aead.Open(nil, sealed.Nonce, sealed.Ciphertext, lookupID)
	if err != nil {
		return nil, ErrAuth
	}
	return pt, nil
}

// Burn performs the same work as opening a passphrase-protected Secret and
// discards the result. Paths that must look like a wrong-passphrase attempt
// (not found, malformed token, passphrase sent to a passphrase-less Secret)
// call it so every request carrying a Passphrase runs exactly one Argon2id.
func (s *Sealer) Burn(ctx context.Context) error {
	_, err := s.Open(ctx, s.dummy, s.dummyKey, nil, []byte("decoy-passphrase"))
	if err != nil && !errors.Is(err, ErrAuth) {
		return err
	}
	return nil
}

func (s *Sealer) aead(ctx context.Context, secretKey, salt, passphrase []byte) (cipher.AEAD, error) {
	ikm, info := secretKey, infoKey
	if passphrase != nil {
		pk, err := s.argon(ctx, passphrase, salt)
		if err != nil {
			return nil, err
		}
		ikm = make([]byte, 0, len(secretKey)+len(pk))
		ikm = append(ikm, secretKey...)
		ikm = append(ikm, pk...)
		info = infoPass
	}
	key, err := hkdf.Key(sha256.New, ikm, salt, info, keyLen)
	if err != nil {
		return nil, fmt.Errorf("seal: hkdf: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("seal: aes: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("seal: gcm: %w", err)
	}
	return aead, nil
}

func (s *Sealer) argon(ctx context.Context, passphrase, salt []byte) ([]byte, error) {
	start := time.Now()
	select {
	case s.sem <- struct{}{}:
	case <-ctx.Done():
		return nil, fmt.Errorf("seal: waiting for kdf slot: %w", ctx.Err())
	}
	defer func() { <-s.sem }()
	if s.onWait != nil {
		s.onWait(time.Since(start))
	}
	return argon2.IDKey(passphrase, salt, s.params.ArgonTime, s.params.ArgonMemoryKiB, 1, keyLen), nil
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}
