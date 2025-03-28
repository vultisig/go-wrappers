package session_test

import (
	session "go-wrapper/go-dkls/sessions"
	testHelper "go-wrapper/go-dkls/test"
	"testing"
)

func RunQcLoop(t *testing.T, parties []P) ([]session.Handle, error) {
	msgq := make(map[string][][]byte)
	n := len(parties)

	shares := make([]session.Handle, 0, n)

	finishedSessions := make(map[session.Handle]bool)

	for len(shares) != n {
		for _, party := range parties {
			for {
				buf, err := session.DklsQcSessionOutputMessage(party.Session)
				if err != nil {
					return nil, err
				}

				if buf == nil {
					break
				}

				for idx := 0; idx < n; idx++ {
					receiver, err := session.DklsQcSessionMessageReceiver(
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
			if finishedSessions[party.Session] {
				continue
			}

			for _, msg := range msgq[party.ID] {
				finished, err := session.DklsQcSessionInputMessage(
					party.Session,
					msg,
				)

				if err != nil {
					return nil, err
				}

				if finished {
					finishedSessions[party.Session] = true
					share, err := session.DklsQcSessionFinish(party.Session)
					if err != nil {
						t.Logf("qc-finish %v failed %v", party.ID, err)
						return nil, err
					}

					shares = append(shares, share)
				}
			}
		}
	}

	return shares, nil
}

func TestQc(t *testing.T) {
	oldShares, err := testHelper.RunKeygen(2, 5)
	if err != nil {
		t.Errorf("error %v", err)
	}

	ids := []string{"p1", "p2", "p3", "p4"}

	setup, err := session.DklsQcSetupMsgNew(
		oldShares[0],
		2,
		ids,
		[]int{0, 1},
		[]int{1, 2, 3},
	)

	if err != nil {
		t.Errorf("dkls-qc-setupmg-new error %v", err)
	}

	p1, err := session.DklsQcSessionFromSetup(setup, "p1", oldShares[0])
	if err != nil {
		t.Errorf("qc-session-from-setup error %v", err)
	}

	p2, err := session.DklsQcSessionFromSetup(setup, "p2", oldShares[1])
	if err != nil {
		t.Errorf("qc-session-from-setup error %v", err)
	}

	p3, err := session.DklsQcSessionFromSetup(setup, "p3", session.Handle(0))
	if err != nil {
		t.Errorf("qc-session-from-setup error %v", err)
	}

	p4, err := session.DklsQcSessionFromSetup(setup, "p4", session.Handle(0))
	if err != nil {
		t.Errorf("qc-session-from-setup error %v", err)
	}

	parties := []P{
		{Session: p1, ID: "p1"},
		{Session: p2, ID: "p2"},
		{Session: p3, ID: "p3"},
		{Session: p4, ID: "p4"},
	}

	shares, err := RunQcLoop(t, parties)
	if err != nil {
		t.Errorf("QC failed %v", err)
	}

	_ = shares
}
