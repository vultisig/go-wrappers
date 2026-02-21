package mldsa_test

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vultisig/go-wrappers/mldsa"
)

func RunSignLoop(parties []Participant) ([][]byte, error) {
	msgq := make(map[string][][]byte)
	n := len(parties)

	shares := make([][]byte, 0, n)

	for len(shares) != n {
		for _, party := range parties {
			for {
				buf, err := mldsa.MldsaSignSessionOutputMessage(party.Session)
				if err != nil {
					return nil, err
				}

				if buf == nil {
					break
				}

				for idx := range n {
					receiver, err := mldsa.MldsaSignSessionMessageReceiver(
						party.Session,
						buf,
						idx,
					)
					if err != nil {
						return nil, err
					}

					if receiver == "" {
						break
					}

					msgq[receiver] = append(msgq[receiver], buf)
				}
			}
		}

		for _, party := range parties {
			for _, msg := range msgq[party.ID] {
				finished, err := mldsa.MldsaSignSessionInputMessage(
					party.Session,
					msg,
				)
				if err != nil {
					return nil, err
				}

				if finished {
					share, err := mldsa.MldsaSignSessionFinish(party.Session)
					if err != nil {
						return nil, err
					}

					shares = append(shares, share)
				}
			}
		}
	}

	return shares, nil
}

// RunSign runs keygen then sign for the given security level and (threshold, n). Returns signatures.
func RunSign(t *testing.T, level mldsa.SecurityLevel, threshold int, n int) ([][]byte, error) {
	shares, err := RunKeygen(t, level, threshold, n)
	if err != nil {
		return nil, err
	}

	ids := PrepareIDSlice(threshold)

	keyID, _ := mldsa.MldsaKeyshareKeyID(shares[0])
	var msgHash [32]byte

	rand.Read(msgHash[:])
	setupMsg, err := mldsa.MldsaSignSetupMsgNew(
		level,
		keyID,
		"m",
		msgHash[:],
		ids,
	)
	if err != nil {
		return nil, err
	}

	msg, err := mldsa.MldsaDecodeMessage(setupMsg)
	assert.NoError(t, err)
	assert.Equal(t, msg, msgHash[:])
	keyID2, err := mldsa.MldsaDecodeKeyID(setupMsg)
	assert.NoError(t, err)
	assert.Equal(t, keyID2, keyID)
	parties := make([]Participant, threshold)

	for i := 1; i <= threshold; i++ {
		id := fmt.Sprintf("p%d", i)
		bytesID := ([]byte)(id)

		sessionHandle, err := mldsa.MldsaSignSessionFromSetup(
			level,
			setupMsg,
			bytesID,
			shares[i-1],
		)
		if err != nil {
			return nil, err
		}

		parties[i-1] = Participant{
			Session: sessionHandle,
			ID:      id,
		}
	}

	return RunSignLoop(parties)
}

const signAttemptsDefault = 25
const signAttempts3x3 = 40

func attempt(t *testing.T, tries int, body func() error) {
	for range tries {
		if err := body(); err != nil {
			if err == mldsa.RejectSamplingError {
				continue
			} else {
				t.Errorf("error %v", err)
			}
		} else {
			return // finally!
		}
	}

	t.Error("too many attempts")
}

func TestSign_2x2(t *testing.T) {
	attempt(t, signAttemptsDefault, func() error {
		_, err := RunSign(t, mldsa.MlDsa87, 2, 2)
		return err
	})
}

func TestSign_2x3(t *testing.T) {
	attempt(t, signAttemptsDefault, func() error {
		_, err := RunSign(t, mldsa.MlDsa87, 2, 3)
		return err
	})
}

func TestSign_3x3(t *testing.T) {
	attempt(t, signAttempts3x3, func() error {
		_, err := RunSign(t, mldsa.MlDsa87, 3, 3)
		return err
	})
}
func TestSign_Level44_2x2(t *testing.T) {
	attempt(t, signAttemptsDefault, func() error {
		_, err := RunSign(t, mldsa.MlDsa44, 2, 2)
		return err
	})
}
func TestSign_Level44_2x3(t *testing.T) {
	attempt(t, signAttemptsDefault, func() error {
		_, err := RunSign(t, mldsa.MlDsa44, 2, 3)
		return err
	})
}
func TestSign_Level44_3x3(t *testing.T) {
	attempt(t, signAttempts3x3, func() error {
		_, err := RunSign(t, mldsa.MlDsa44, 3, 3)
		return err
	})
}
func TestSign_Level65_2x2(t *testing.T) {
	attempt(t, signAttemptsDefault, func() error {
		_, err := RunSign(t, mldsa.MlDsa65, 2, 2)
		return err
	})
}
func TestSign_Level65_2x3(t *testing.T) {
	attempt(t, signAttemptsDefault, func() error {
		_, err := RunSign(t, mldsa.MlDsa65, 2, 3)
		return err
	})
}
func TestSign_Level65_3x3(t *testing.T) {
	attempt(t, signAttempts3x3, func() error {
		_, err := RunSign(t, mldsa.MlDsa65, 3, 3)
		return err
	})
}
func TestSign_Level87_2x2(t *testing.T) {
	attempt(t, signAttemptsDefault, func() error {
		_, err := RunSign(t, mldsa.MlDsa87, 2, 2)
		return err
	})
}
func TestSign_Level87_2x3(t *testing.T) {
	attempt(t, signAttemptsDefault, func() error {
		_, err := RunSign(t, mldsa.MlDsa87, 2, 3)
		return err
	})
}
func TestSign_Level87_3x3(t *testing.T) {
	attempt(t, signAttempts3x3, func() error {
		_, err := RunSign(t, mldsa.MlDsa87, 3, 3)
		return err
	})
}
