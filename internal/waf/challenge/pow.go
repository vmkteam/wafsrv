package challenge

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"
)

// PowConfig holds PoW challenge configuration.
type PowConfig struct {
	Difficulty       int           // maxNumber for normal mode (default 50000)
	AttackDifficulty int           // maxNumber for Under Attack Mode (default 500000)
	Timeout          time.Duration // client-side timeout (default 10s)
	SaltTTL          time.Duration // salt expiry for anti-replay (default 5m)
}

// PowChallenge is sent to the client embedded in HTML.
type PowChallenge struct {
	Algorithm string `json:"algorithm"`
	Challenge string `json:"challenge"`
	Salt      string `json:"salt"`
	MaxNumber int    `json:"maxNumber"`
	Signature string `json:"signature"`
}

// PowPayload is the client's solution submitted via cookie.
type PowPayload struct {
	Algorithm string `json:"algorithm"`
	Challenge string `json:"challenge"`
	Number    int    `json:"number"`
	Salt      string `json:"salt"`
	Signature string `json:"signature"`
}

// PowVerifier handles PoW challenge generation and verification.
type PowVerifier struct {
	secret        []byte
	cfg           PowConfig
	adaptiveState func() bool // returns true if under attack
}

// NewPowVerifier creates a new PoW verifier.
func NewPowVerifier(secret []byte, cfg PowConfig, adaptiveState func() bool) *PowVerifier {
	if cfg.Difficulty == 0 {
		cfg.Difficulty = 50000
	}

	if cfg.AttackDifficulty == 0 {
		cfg.AttackDifficulty = 500000
	}

	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Second
	}

	if cfg.SaltTTL == 0 {
		cfg.SaltTTL = 5 * time.Minute
	}

	return &PowVerifier{
		secret:        secret,
		cfg:           cfg,
		adaptiveState: adaptiveState,
	}
}

// GenerateChallenge creates a new PoW challenge bound to the client's IP and User-Agent.
func (v *PowVerifier) GenerateChallenge(clientIP, userAgent string) PowChallenge {
	// single rand.Read: 12 bytes for salt uniqueness + 4 bytes for secret number
	rb := make([]byte, 16)
	_, _ = rand.Read(rb)

	// bind to client: hash of IP + UA
	binding := clientBinding(clientIP, userAgent)

	// salt = random.binding.timestamp
	salt := hex.EncodeToString(rb[:12]) + "." + binding + "." + strconv.FormatInt(time.Now().Unix(), 10)

	maxNumber := v.currentDifficulty()

	// pick a random secret number in [0, maxNumber]
	number := randInt(rb[12:], maxNumber)

	// challenge = SHA-256(salt + number)
	challengeHash := sha256Hex(salt + strconv.Itoa(number))

	// signature = HMAC-SHA256(server_secret, challenge)
	signature := hmacSHA256Hex(v.secret, challengeHash)

	return PowChallenge{
		Algorithm: "SHA-256",
		Challenge: challengeHash,
		Salt:      salt,
		MaxNumber: maxNumber,
		Signature: signature,
	}
}

// VerifySolution checks a PoW solution. O(1) — one SHA-256 + HMAC check.
func (v *PowVerifier) VerifySolution(payload PowPayload, clientIP, userAgent string) bool {
	if payload.Algorithm != "SHA-256" {
		return false
	}

	// 1. verify signature (stateless)
	expectedSig := hmacSHA256Hex(v.secret, payload.Challenge)
	if !hmac.Equal([]byte(payload.Signature), []byte(expectedSig)) {
		return false
	}

	// 2. verify solution: SHA-256(salt + number) == challenge
	expectedChallenge := sha256Hex(payload.Salt + strconv.Itoa(payload.Number))
	if expectedChallenge != payload.Challenge {
		return false
	}

	// 3. verify client binding (IP + UA)
	parts := strings.SplitN(payload.Salt, ".", 3)
	if len(parts) != 3 {
		return false
	}

	expectedBinding := clientBinding(clientIP, userAgent)
	if parts[1] != expectedBinding {
		return false
	}

	// 4. verify timestamp (anti-replay)
	ts, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		return false
	}

	if time.Since(time.Unix(ts, 0)) > v.cfg.SaltTTL {
		return false
	}

	return true
}

// Timeout returns the configured client-side timeout.
func (v *PowVerifier) Timeout() time.Duration {
	return v.cfg.Timeout
}

func (v *PowVerifier) currentDifficulty() int {
	if v.adaptiveState != nil && v.adaptiveState() {
		return v.cfg.AttackDifficulty
	}

	return v.cfg.Difficulty
}

// DecodePowPayload decodes a base64-encoded PoW cookie value.
func DecodePowPayload(cookieValue string) (PowPayload, error) {
	data, err := base64.StdEncoding.DecodeString(cookieValue)
	if err != nil {
		// try URL-safe base64
		data, err = base64.URLEncoding.DecodeString(cookieValue)
		if err != nil {
			return PowPayload{}, fmt.Errorf("challenge: invalid pow payload encoding: %w", err)
		}
	}

	var p PowPayload
	if err := json.Unmarshal(data, &p); err != nil {
		return PowPayload{}, fmt.Errorf("challenge: invalid pow payload: %w", err)
	}

	return p, nil
}

// clientBinding returns a short hash binding the challenge to IP + User-Agent.
func clientBinding(clientIP, userAgent string) string {
	h := sha256.Sum256([]byte(clientIP + "|" + userAgent))
	return hex.EncodeToString(h[:8])
}

// sha256Hex returns hex-encoded SHA-256 hash.
func sha256Hex(data string) string {
	h := sha256.Sum256([]byte(data))
	return hex.EncodeToString(h[:])
}

// hmacSHA256Hex returns hex-encoded HMAC-SHA256.
func hmacSHA256Hex(secret []byte, data string) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(data))

	return hex.EncodeToString(mac.Sum(nil))
}

// randInt returns an unbiased random int in [0, max] using provided random bytes as seed.
// Falls back to crypto/rand.Int for unbiased sampling.
func randInt(seed []byte, upperBound int) int {
	if upperBound <= 0 {
		return 0
	}

	// Use crypto/rand.Int for unbiased distribution
	n, err := rand.Int(rand.Reader, big.NewInt(int64(upperBound+1)))
	if err != nil {
		// fallback: use seed bytes
		v := int(seed[0])<<24 | int(seed[1])<<16 | int(seed[2])<<8 | int(seed[3])
		if v < 0 {
			v = -v
		}

		return v % (upperBound + 1)
	}

	return int(n.Int64())
}
