package test

import (
	"fmt"
	"strings"

	session "github.com/vultisig/go-wrappers/go-dkls/sessions"
)

type TestInput struct {
	T int
	N int
}

type Participant struct {
	Session session.Handle
	ID      string
}

// returns the valid Ids slice
func PrepareIDSlice(n int) []byte {
	keys := []string{}
	for p := 1; p <= n; p++ {
		keys = append(keys, fmt.Sprintf("p%d", p))
	}

	return ([]byte)(strings.Join(keys, "\x00"))
}

func RunKeygenLoop(parties []Participant) ([]session.Handle, error) {
	msgq := make(map[string][][]byte)
	n := len(parties)

	shares := make([]session.Handle, 0, n)

	for len(shares) != n {
		for _, party := range parties {
			for {
				buf, err := session.DklsKeygenSessionOutputMessage(party.Session)
				if err != nil {
					return nil, err
				}

				if buf == nil {
					break
				}

				for idx := 0; idx < n; idx++ {
					receiver, err := session.DklsKeygenSessionMessageReceiver(
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
				finished, err := session.DklsKeygenSessionInputMessage(
					party.Session,
					msg,
				)
				if err != nil {
					return nil, err
				}

				if finished {
					share, err := session.DklsKeygenSessionFinish(party.Session)
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

func RunKeygen(t int, n int) ([]session.Handle, error) {
	ids := PrepareIDSlice(n)

	setupMsg, err := session.DklsKeygenSetupMsgNew(t, nil, ids)
	if err != nil {
		return nil, err
	}

	parties := make([]Participant, n)

	for i := 1; i <= n; i++ {
		id := fmt.Sprintf("p%d", i)
		bytesID := ([]byte)(id)

		sessionHandle, err := session.DklsKeygenSessionFromSetup(setupMsg, bytesID)
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

func RunSign(shares []session.Handle, msg []byte) ([][]byte, error) {
	t := len(shares)

	keyID, err := session.DklsKeyshareKeyID(shares[0])
	if err != nil {
		return nil, err
	}

	ids := PrepareIDSlice(t)

	setup, err := session.DklsSignSetupMsgNew(
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

		sessionHandle, err := session.DklsSignSessionFromSetup(
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

	sh, err := runSignLoop(parties)

	return sh, err
}

func RunPresign(shares []session.Handle) ([][]byte, error) {
	t := len(shares)

	keyID, err := session.DklsKeyshareKeyID(shares[0])
	if err != nil {
		return nil, err
	}

	ids := PrepareIDSlice(t)

	setup, err := session.DklsSignSetupMsgNew(
		keyID,
		nil,
		nil,
		ids,
	)
	if err != nil {
		return nil, err
	}

	parties := make([]Participant, t)

	for i := 1; i <= t; i++ {
		id := fmt.Sprintf("p%d", i)
		bytesID := ([]byte)(id)

		sessionHandle, err := session.DklsSignSessionFromSetup(
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

	sh, err := runSignLoop(parties)

	return sh, err
}

func RunFinish(presign []session.Handle, msg []byte) ([][]byte, error) {
	t := len(presign)

	sessionID, err := session.DklsPresignSessionID(presign[0])
	if err != nil {
		return nil, err
	}

	ids := PrepareIDSlice(t)

	setup, err := session.DklsFinishSetupMsgNew(
		sessionID,
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

		sessionHandle, err := session.DklsSignSessionFromSetup(
			setup,
			bytesID,
			presign[i-1],
		)
		if err != nil {
			return nil, err
		}

		parties[i-1] = Participant{
			Session: sessionHandle,
			ID:      id,
		}
	}

	shares, err := runSignLoop(parties)

	return shares, err
}

func runSignLoop(parties []Participant) ([][]byte, error) {
	msgq := make(map[string][][]byte)

	t := len(parties)
	shares := make([][]byte, 0, t)

	for len(shares) != t {
		for _, party := range parties {
			for {
				buf, err := session.DklsSignSessionOutputMessage(party.Session)
				if err != nil {
					return nil, err
				}

				if len(buf) == 0 {
					break
				}

				for idx := 0; idx < t; idx++ {
					receiver, err := session.DklsSignSessionMessageReceiver(
						party.Session,
						buf,
						idx,
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
				finished, err := session.DklsSignSessionInputMessage(party.Session, msg)
				if err != nil {
					return nil, err
				}

				if finished {
					sign, err := session.DklsSignSessionFinish(party.Session)
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
