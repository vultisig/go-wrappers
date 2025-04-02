package test

import (
	"fmt"
	"strings"

	session "github.com/vultisig/go-wrapper/go-schnorr/sessions"
)

type TestInput struct {
	T int
	N int
}

type Participant struct {
	Session session.Handle
	ID      string
}

// returns the valid Ids slice, along with the msgq map
func PrepareIDSlice(n int) []byte {
	keys := []string{}
	for p := 1; p <= n; p++ {
		keys = append(keys, fmt.Sprintf("p%d", p))
	}

	return ([]byte)(strings.Join(keys, "\x00"))
}

func RunSchnorrKeygenLoop(parties []Participant) ([]session.Handle, error) {
	msgq := make(map[string][][]byte)
	n := len(parties)

	shares := make([]session.Handle, 0, n)

	for len(shares) != n {
		for _, party := range parties {
			for {
				buf, err := session.SchnorrKeygenSessionOutputMessage(party.Session)
				if err != nil {
					return nil, err
				}

				if buf == nil {
					break
				}

				for idx := 0; idx < n; idx++ {
					receiver, err := session.SchnorrKeygenSessionMessageReceiver(
						party.Session,
						buf,
						uint32(idx),
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
				finished, err := session.SchnorrKeygenSessionInputMessage(
					party.Session,
					msg,
				)
				if err != nil {
					return nil, err
				}

				if finished {
					share, err := session.SchnorrKeygenSessionFinish(party.Session)
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

func RunSchnorrKeygen(t int, n int) ([]session.Handle, error) {
	ids := PrepareIDSlice(n)

	setupMsg, err := session.SchnorrKeygenSetupMsgNew(int32(t), nil, ids)
	if err != nil {
		return nil, err
	}

	parties := make([]Participant, n)

	for i := 1; i <= n; i++ {
		id := fmt.Sprintf("p%d", i)
		bytesID := ([]byte)(id)

		sessionHandle, err := session.SchnorrKeygenSessionFromSetup(setupMsg, bytesID)
		if err != nil {
			return nil, err
		}

		parties[i-1] = Participant{
			Session: sessionHandle,
			ID:      id,
		}
	}

	return RunSchnorrKeygenLoop(parties)
}

func RunSchnorrSign(shares []session.Handle, msg []byte) ([][]byte, error) {
	t := len(shares)

	keyID, err := session.SchnorrKeyshareKeyID(shares[0])
	if err != nil {
		return nil, err
	}

	ids := PrepareIDSlice(t)

	setup, err := session.SchnorrSignSetupMsgNew(
		keyID,
		nil,
		msg,
		ids,
	)
	if err != nil {
		return nil, err
	}

	parties := make([]Participant, t)

	for i := 1; i <= t; i++ {
		id := fmt.Sprintf("p%d", i)
		bytesID := ([]byte)(id)

		sessionHandle, err := session.SchnorrSignSessionFromSetup(
			setup,
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

	sh, err := runSchnorrSignLoop(parties)

	return sh, err
}

func runSchnorrSignLoop(parties []Participant) ([][]byte, error) {
	msgq := make(map[string][][]byte)

	t := len(parties)
	shares := make([][]byte, 0, t)

	for len(shares) != t {
		for _, party := range parties {
			for {
				buf, err := session.SchnorrSignSessionOutputMessage(party.Session)
				if err != nil {
					return nil, err
				}

				if len(buf) == 0 {
					break
				}

				for idx := 0; idx < t; idx++ {
					receiver, err := session.SchnorrSignSessionMessageReceiver(
						party.Session,
						buf,
						uint32(idx),
					)
					if err != nil {
						return nil, err
					}

					if len(receiver) == 0 {
						break
					}

					msgq[string(receiver)] = append(msgq[string(receiver)], buf)
				}
			}
		}

		for _, party := range parties {
			for _, msg := range msgq[party.ID] {
				finished, err := session.SchnorrSignSessionInputMessage(party.Session, msg)
				if err != nil {
					return nil, err
				}

				if finished {
					sign, err := session.SchnorrSignSessionFinish(party.Session)
					if err != nil {
						return nil, err
					}

					shares = append(shares, sign)
				}
			}
		}
	}

	return shares, nil
}
