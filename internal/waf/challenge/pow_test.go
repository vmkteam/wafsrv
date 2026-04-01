package challenge

import (
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
)

type PowSuite struct {
	suite.Suite
	verifier *PowVerifier
}

func TestPowSuite(t *testing.T) {
	suite.Run(t, new(PowSuite))
}

func (s *PowSuite) SetupTest() {
	s.verifier = NewPowVerifier([]byte("test-secret"), PowConfig{
		Difficulty:       1000,
		AttackDifficulty: 5000,
		Timeout:          10 * time.Second,
		SaltTTL:          5 * time.Minute,
	}, nil)
}

func (s *PowSuite) TestGenerateChallenge() {
	ch := s.verifier.GenerateChallenge("1.2.3.4", "Mozilla/5.0")

	s.Equal("SHA-256", ch.Algorithm)
	s.NotEmpty(ch.Challenge)
	s.NotEmpty(ch.Salt)
	s.NotEmpty(ch.Signature)
	s.Equal(1000, ch.MaxNumber)

	// salt has 3 parts: random.binding.timestamp
	parts := strings.SplitN(ch.Salt, ".", 3)
	s.Len(parts, 3)
	s.Len(parts[0], 24) // 12 bytes hex
	s.Len(parts[1], 16) // 8 bytes hex
}

func (s *PowSuite) TestVerifySolution() {
	ch := s.verifier.GenerateChallenge("1.2.3.4", "Mozilla/5.0")

	// brute-force the solution (small difficulty for test)
	number := s.solvePow(ch)
	s.GreaterOrEqual(number, 0)

	payload := PowPayload{
		Algorithm: ch.Algorithm,
		Challenge: ch.Challenge,
		Number:    number,
		Salt:      ch.Salt,
		Signature: ch.Signature,
	}

	s.True(s.verifier.VerifySolution(payload, "1.2.3.4", "Mozilla/5.0"))
}

func (s *PowSuite) TestVerifyWrongNumber() {
	ch := s.verifier.GenerateChallenge("1.2.3.4", "Mozilla/5.0")
	number := s.solvePow(ch)

	payload := PowPayload{
		Algorithm: ch.Algorithm,
		Challenge: ch.Challenge,
		Number:    number + 1, // wrong
		Salt:      ch.Salt,
		Signature: ch.Signature,
	}

	s.False(s.verifier.VerifySolution(payload, "1.2.3.4", "Mozilla/5.0"))
}

func (s *PowSuite) TestVerifyWrongIP() {
	ch := s.verifier.GenerateChallenge("1.2.3.4", "Mozilla/5.0")
	number := s.solvePow(ch)

	payload := PowPayload{
		Algorithm: ch.Algorithm,
		Challenge: ch.Challenge,
		Number:    number,
		Salt:      ch.Salt,
		Signature: ch.Signature,
	}

	s.False(s.verifier.VerifySolution(payload, "5.6.7.8", "Mozilla/5.0"))
}

func (s *PowSuite) TestVerifyWrongUA() {
	ch := s.verifier.GenerateChallenge("1.2.3.4", "Mozilla/5.0")
	number := s.solvePow(ch)

	payload := PowPayload{
		Algorithm: ch.Algorithm,
		Challenge: ch.Challenge,
		Number:    number,
		Salt:      ch.Salt,
		Signature: ch.Signature,
	}

	s.False(s.verifier.VerifySolution(payload, "1.2.3.4", "curl/7.0"))
}

func (s *PowSuite) TestVerifyExpiredSalt() {
	v := NewPowVerifier([]byte("test-secret"), PowConfig{
		Difficulty: 1000,
		SaltTTL:    1 * time.Millisecond,
	}, nil)

	ch := v.GenerateChallenge("1.2.3.4", "Mozilla/5.0")
	number := s.solvePowWith(ch)

	time.Sleep(5 * time.Millisecond)

	payload := PowPayload{
		Algorithm: ch.Algorithm,
		Challenge: ch.Challenge,
		Number:    number,
		Salt:      ch.Salt,
		Signature: ch.Signature,
	}

	s.False(v.VerifySolution(payload, "1.2.3.4", "Mozilla/5.0"))
}

func (s *PowSuite) TestVerifyTamperedSignature() {
	ch := s.verifier.GenerateChallenge("1.2.3.4", "Mozilla/5.0")
	number := s.solvePow(ch)

	payload := PowPayload{
		Algorithm: ch.Algorithm,
		Challenge: ch.Challenge,
		Number:    number,
		Salt:      ch.Salt,
		Signature: "deadbeef",
	}

	s.False(s.verifier.VerifySolution(payload, "1.2.3.4", "Mozilla/5.0"))
}

func (s *PowSuite) TestVerifyWrongAlgorithm() {
	ch := s.verifier.GenerateChallenge("1.2.3.4", "Mozilla/5.0")
	number := s.solvePow(ch)

	payload := PowPayload{
		Algorithm: "SHA-512",
		Challenge: ch.Challenge,
		Number:    number,
		Salt:      ch.Salt,
		Signature: ch.Signature,
	}

	s.False(s.verifier.VerifySolution(payload, "1.2.3.4", "Mozilla/5.0"))
}

func (s *PowSuite) TestAdaptiveDifficulty() {
	underAttack := false
	v := NewPowVerifier([]byte("test-secret"), PowConfig{
		Difficulty:       1000,
		AttackDifficulty: 5000,
	}, func() bool { return underAttack })

	ch1 := v.GenerateChallenge("1.2.3.4", "Mozilla/5.0")
	s.Equal(1000, ch1.MaxNumber)

	underAttack = true
	ch2 := v.GenerateChallenge("1.2.3.4", "Mozilla/5.0")
	s.Equal(5000, ch2.MaxNumber)
}

func (s *PowSuite) TestDecodePowPayload() {
	payload := PowPayload{
		Algorithm: "SHA-256",
		Challenge: "abc123",
		Number:    42,
		Salt:      "salt.binding.123",
		Signature: "sig",
	}

	data, err := json.Marshal(payload)
	s.Require().NoError(err)

	encoded := base64.StdEncoding.EncodeToString(data)

	decoded, err := DecodePowPayload(encoded)
	s.Require().NoError(err)
	s.Equal(payload, decoded)
}

func (s *PowSuite) TestDecodePowPayloadInvalid() {
	_, err := DecodePowPayload("not-base64!!!")
	s.Require().Error(err)

	_, err = DecodePowPayload(base64.StdEncoding.EncodeToString([]byte("not json")))
	s.Require().Error(err)
}

func (s *PowSuite) TestVerifyMalformedSalt() {
	ch := s.verifier.GenerateChallenge("1.2.3.4", "Mozilla/5.0")

	payload := PowPayload{
		Algorithm: ch.Algorithm,
		Challenge: ch.Challenge,
		Number:    0,
		Salt:      "no-dots-here",
		Signature: hmacSHA256Hex(s.verifier.secret, ch.Challenge),
	}

	s.False(s.verifier.VerifySolution(payload, "1.2.3.4", "Mozilla/5.0"))
}

func (s *PowSuite) TestDefaultConfig() {
	v := NewPowVerifier([]byte("s"), PowConfig{}, nil)
	s.Equal(50000, v.cfg.Difficulty)
	s.Equal(500000, v.cfg.AttackDifficulty)
	s.Equal(10*time.Second, v.cfg.Timeout)
	s.Equal(5*time.Minute, v.cfg.SaltTTL)
}

// solvePow brute-forces the solution for a challenge.
func (s *PowSuite) solvePow(ch PowChallenge) int {
	s.T().Helper()

	return s.solvePowWith(ch)
}

func (s *PowSuite) solvePowWith(ch PowChallenge) int {
	s.T().Helper()

	for n := 0; n <= ch.MaxNumber; n++ {
		hash := sha256Hex(ch.Salt + strconv.Itoa(n))
		if hash == ch.Challenge {
			return n
		}
	}

	s.Fail("failed to solve PoW challenge")

	return -1
}

func BenchmarkPowGenerate(b *testing.B) {
	v := NewPowVerifier([]byte("bench-secret"), PowConfig{Difficulty: 50000}, nil)

	b.ResetTimer()
	for b.Loop() {
		v.GenerateChallenge("1.2.3.4", "Mozilla/5.0")
	}
}

func BenchmarkPowVerify(b *testing.B) {
	v := NewPowVerifier([]byte("bench-secret"), PowConfig{Difficulty: 100}, nil)
	ch := v.GenerateChallenge("1.2.3.4", "Mozilla/5.0")

	// solve once
	var number int
	for n := 0; n <= ch.MaxNumber; n++ {
		if sha256Hex(ch.Salt+strconv.Itoa(n)) == ch.Challenge {
			number = n
			break
		}
	}

	payload := PowPayload{
		Algorithm: ch.Algorithm,
		Challenge: ch.Challenge,
		Number:    number,
		Salt:      ch.Salt,
		Signature: ch.Signature,
	}

	b.ResetTimer()
	for b.Loop() {
		v.VerifySolution(payload, "1.2.3.4", "Mozilla/5.0")
	}
}
