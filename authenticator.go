package csrf

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"log"
	"math/big"
	"math/rand"
	"sort"
	"time"
)

// Create an Authenticator with site-specific values
type Authenticator struct {
	// Key should be approximately 64 bytes of unguessable data
	Key []byte
	// Each character of a token supplies 3.02 bits of security.
	// Recommended values are 12 - 40. The maximum effective length
	// is 168. Higher values work correctly but do not provide any
	// additional security.
	TokenLength int
	// Tokens remain valid for at least Lifetime, and no more
	// than twice Lifetime. Lower values provide better security,
	// higher values provide better user experience.
	Lifetime time.Duration
}

// Sorted for binary search in ValidateToken()
var urlSafe = []byte{
	'-', '.',
	'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
	'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
	'_',
	'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
	'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
	'~',
}

// GenerateToken() creates a new token in the given session. Date should be
// the current time and session should uniquely identify the user, such as
// []byte(username) or a session token.
func (a *Authenticator) GenerateToken(date time.Time, session []byte) string {
	saltLength := a.TokenLength / 2
	randomSalt := make([]byte, saltLength)
	for i := range randomSalt {
		randomSalt[i] = urlSafe[rand.Int31n(int32(len(urlSafe)))]
	}

	counter := date.UnixNano() / int64(a.Lifetime)
	token := a.generateTokenWithSalt(counter, session, randomSalt)
	return token
}

func (a *Authenticator) generateTokenWithSalt(counter int64, session, salt []byte) string {
	token := a.generateByteTokenWithSalt(counter, session, salt)
	return string(token)
}

func (a *Authenticator) generateByteTokenWithSalt(counter int64, session, salt []byte) []byte {
	var counterBytes [8]byte
	binary.BigEndian.PutUint64(counterBytes[:], uint64(counter))

	h := hmac.New(sha512.New, a.Key)
	h.Write(counterBytes[:])
	h.Write(session)
	h.Write(salt)

	var hashArray [sha512.Size]byte
	sumBytes := h.Sum(hashArray[:0])

	token := make([]byte, a.TokenLength)
	hashLength := a.TokenLength - len(salt)

	var sum, base big.Int
	sum.SetBytes(sumBytes)
	base.SetUint64(uint64(len(urlSafe)))
	for i := 0; i < hashLength; i++ {
		var remainder big.Int
		sum.QuoRem(&sum, &base, &remainder)
		remainder.Abs(&remainder)
		token[i] = urlSafe[remainder.Uint64()]
	}

	copy(token[hashLength:], salt)
	return token
}

// ValidateToken() returns true if the token is valid for given time and
// session. Date should be the current time. Session must be the same
// identifier used when generating the token.
func (a *Authenticator) ValidateToken(date time.Time, session []byte, token string) bool {
	if len(token) != a.TokenLength {
		log.Printf("CheckToken() invalid length: %d", len(token))
		return false
	}

	tokenBytes := []byte(token)
	saltLength := len(tokenBytes) / 2
	hashLength := len(tokenBytes) - saltLength
	salt := tokenBytes[hashLength:]
	for _, c := range salt {
		i := sort.Search(len(urlSafe), func(i int) bool {
			return urlSafe[i] >= c
		})
		if urlSafe[i] != c {
			// invalid character
			log.Printf("CheckToken() invalid character: %c", c)
			return false
		}
	}

	counter := date.UnixNano() / int64(a.Lifetime)
	token1 := a.generateByteTokenWithSalt(counter, session, salt)
	token2 := a.generateByteTokenWithSalt(counter - 1, session, salt)
	match1 := hmac.Equal(tokenBytes, token1)
	match2 := hmac.Equal(tokenBytes, token2)
	return match1 || match2
}

