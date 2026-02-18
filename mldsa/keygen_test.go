package mldsa_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/vultisig/go-wrappers/mldsa"
)

type Participant struct {
	Session mldsa.Handle
	ID      string
}

func PrepareIDSlice(n int) []byte {
	keys := []string{}
	for p := 1; p <= n; p++ {
		keys = append(keys, fmt.Sprintf("p%d", p))
	}

	return ([]byte)(strings.Join(keys, "\x00"))
}

func TestKeygenSetupNew(t *testing.T) {
	mldsa.MldsaKeygenSetupMsgNew(2, nil, nil)
}

func RunKeygenLoop(parties []Participant) ([]mldsa.Handle, error) {
	msgq := make(map[string][][]byte)
	n := len(parties)

	shares := make([]mldsa.Handle, 0, n)

	for len(shares) != n {
		for _, party := range parties {
			for {
				buf, err := mldsa.MldsaKeygenSessionOutputMessage(party.Session)
				if err != nil {
					return nil, err
				}

				if buf == nil {
					break
				}

				for idx := range n {
					receiver, err := mldsa.MldsaKeygenSessionMessageReceiver(
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
				finished, err := mldsa.MldsaKeygenSessionInputMessage(
					party.Session,
					msg,
				)
				if err != nil {
					return nil, err
				}

				if finished {
					share, err := mldsa.MldsaKeygenSessionFinish(party.Session)
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

func RunKeygen(t int, n int) ([]mldsa.Handle, error) {
	ids := PrepareIDSlice(n)

	setupMsg, err := mldsa.MldsaKeygenSetupMsgNew(t, nil, ids)
	if err != nil {
		return nil, err
	}

	parties := make([]Participant, n)

	for i := 1; i <= n; i++ {
		id := fmt.Sprintf("p%d", i)
		bytesID := ([]byte)(id)

		sessionHandle, err := mldsa.MldsaKeygenSessionFromSetup(setupMsg, bytesID)
		if err != nil {
			return nil, err
		}

		parties[i-1] = Participant{
			Session: sessionHandle,
			ID:      id,
		}
	}

	return RunKeygenLoop(parties)
}

func TestKeygen_2x2(t *testing.T) {
	_, err := RunKeygen(2, 2)

	if err != nil {
		t.Errorf("unexpected error %v", err)
	}
}

func TestKeygen_2x3(t *testing.T) {
	_, err := RunKeygen(2, 3)

	if err != nil {
		t.Errorf("unexpected error %v", err)
	}
}
