package mldsa_test

import (
	"fmt"
	"testing"

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

func RunSign(t int, n int) ([][]byte, error) {
	shares, err := RunKeygen(t, n)
	if err != nil {
		return nil, err
	}

	ids := PrepareIDSlice(t)

	keyID, _ := mldsa.MldsaKeyshareKeyID(shares[0])
	var msgHash [32]byte

	setupMsg, err := mldsa.MldsaSignSetupMsgNew(keyID, "m", msgHash[:], ids)
	if err != nil {
		return nil, err
	}

	parties := make([]Participant, t)

	for i := 1; i <= t; i++ {
		id := fmt.Sprintf("p%d", i)
		bytesID := ([]byte)(id)

		sessionHandle, err := mldsa.MldsaSignSessionFromSetup(
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
	attempt(t, 10, func() error {
		_, err := RunSign(2, 2)
		return err
	})
}

func TestSign_2x3(t *testing.T) {
	attempt(t, 10, func() error {
		_, err := RunSign(2, 3)
		return err
	})
}

func TestSign_3x3(t *testing.T) {
	attempt(t, 10, func() error {
		_, err := RunSign(3, 3)
		return err
	})
}
