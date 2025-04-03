package session_test

import (
	"crypto/ed25519"
	"fmt"
	"testing"

	session "github.com/vultisig/go-wrappers/go-schnorr/sessions"
	testHelper "github.com/vultisig/go-wrappers/go-schnorr/test"

	"github.com/stretchr/testify/assert"
)

func TestSchnorrSignSessionFlow(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name  string
		input testHelper.TestInput
	}{
		{
			name: "schnorr sign session 2x2 success",
			input: testHelper.TestInput{
				T: 2,
				N: 2,
			},
		},
		{
			name: "schnorr sign session 2x3 success",
			input: testHelper.TestInput{
				T: 2,
				N: 3,
			},
		},
		{
			name: "schnorr sign session 3x3 success",
			input: testHelper.TestInput{
				T: 3,
				N: 3,
			},
		},
		{
			name: "schnorr sign session 3x4 success",
			input: testHelper.TestInput{
				T: 3,
				N: 4,
			},
		},
		{
			name: "schnorr sign session 4x4 success",
			input: testHelper.TestInput{
				T: 4,
				N: 4,
			},
		},
		{
			name: "schnorr sign session 4x5 success",
			input: testHelper.TestInput{
				T: 4,
				N: 5,
			},
		},
		{
			name: "schnorr sign session 5x5 success",
			input: testHelper.TestInput{
				T: 5,
				N: 5,
			},
		},
		{
			name: "schnorr sign session 3x5 success",
			input: testHelper.TestInput{
				T: 3,
				N: 5,
			},
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			keygenShares, err := testHelper.RunSchnorrKeygen(tc.input.T, tc.input.N)

			assert.NoError(t, err)
			assert.NotEmpty(t, keygenShares)

			msg := make([]byte, 32)
			for i := range msg {
				msg[i] = 1
			}

			keyID, err := session.SchnorrKeyshareKeyID(keygenShares[0])

			assert.NoError(t, err)
			assert.NotEmpty(t, keyID)

			msgq := make(map[string][][]byte)
			ids := testHelper.PrepareIDSlice(tc.input.T)

			setup, err := session.SchnorrSignSetupMsgNew(
				keyID,
				nil,
				msg,
				ids,
			)

			assert.NoError(t, err)
			assert.NotEmpty(t, setup)

			parties := make([]testHelper.Participant, tc.input.T)

			for i := 1; i <= tc.input.T; i++ {
				id := fmt.Sprintf("p%d", i)
				bytesID := ([]byte)(id)
				sessionHandle, err := session.SchnorrSignSessionFromSetup(
					setup,
					bytesID,
					keygenShares[i-1],
				)

				assert.NoError(t, err)
				assert.NotZero(t, sessionHandle)

				parties[i-1] = testHelper.Participant{
					Session: sessionHandle,
					ID:      id,
				}
			}

			shares := make([][]byte, 0, tc.input.T)

			for len(shares) != tc.input.T {
				for _, party := range parties {
					for {
						buf, err := session.SchnorrSignSessionOutputMessage(party.Session)
						if err != nil {
							t.Logf("WTF")
						}
						assert.NoError(t, err)

						if len(buf) == 0 {
							break
						}

						for idx := 0; idx < tc.input.N; idx++ {
							receiver, err := session.SchnorrSignSessionMessageReceiver(
								party.Session,
								buf,
								uint32(idx),
							)
							assert.NoError(t, err)

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
						assert.NoError(t, err)

						if finished {
							sign, err := session.SchnorrSignSessionFinish(party.Session)

							assert.NoError(t, err)
							assert.NotEmpty(t, sign)

							shares = append(shares, sign)

							err = session.SchnorrSignSessionFree(party.Session)
							assert.NoError(t, err)
						}
					}
				}
			}
		})
	}
}

func TestSign(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		input   testHelper.TestInput
		someInt int
	}{
		{
			name: "test sign 2x3 success",
			input: testHelper.TestInput{
				T: 2,
				N: 3,
			},
			someInt: 1,
		},
		{
			name: "test sign 3x4 success",
			input: testHelper.TestInput{
				T: 3,
				N: 4,
			},
			someInt: 2,
		},
		{
			name: "test sign 3x5 success",
			input: testHelper.TestInput{
				T: 3,
				N: 5,
			},
			someInt: 3,
		},
		{
			name: "test sign 4x5 success",
			input: testHelper.TestInput{
				T: 4,
				N: 5,
			},
			someInt: 4,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// t.Logf("Name: %s\nT: %d\nN: %d", tc.name, tc.input.T, tc.input.N)
			keygenShares, err := testHelper.RunSchnorrKeygen(tc.input.T, tc.input.N)

			assert.NoError(t, err)
			assert.NotEmpty(t, keygenShares)

			pk, err := session.SchnorrKeysharePublicKey(keygenShares[0])

			assert.NoError(t, err)
			assert.NotEmpty(t, pk)

			msg1 := make([]byte, 32)
			for i := range msg1 {
				msg1[i] = 1
			}

			// run full DSG using the first N-1 key shares
			signs, err := testHelper.RunSchnorrSign(keygenShares[:tc.input.N], msg1)

			assert.NoError(t, err)
			assert.NotEmpty(t, signs)

			// and verify signatures
			for _, s := range signs {
				verified := ed25519.Verify(pk, msg1, s)
				assert.True(t, verified)
			}
		})
	}
}

func TestSchnorrSign(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name  string
		input testHelper.TestInput
	}{
		{
			name: "schnorr sign session 2x2 success",
			input: testHelper.TestInput{
				T: 2,
				N: 2,
			},
		},
		{
			name: "schnorr sign session 2x3 success",
			input: testHelper.TestInput{
				T: 2,
				N: 3,
			},
		},
		{
			name: "schnorr sign session 3x3 success",
			input: testHelper.TestInput{
				T: 3,
				N: 3,
			},
		},
		{
			name: "schnorr sign session 3x4 success",
			input: testHelper.TestInput{
				T: 3,
				N: 4,
			},
		},
		{
			name: "schnorr sign session 4x4 success",
			input: testHelper.TestInput{
				T: 4,
				N: 4,
			},
		},
		{
			name: "schnorr sign session 4x5 success",
			input: testHelper.TestInput{
				T: 4,
				N: 5,
			},
		},
		{
			name: "schnorr sign session 5x5 success",
			input: testHelper.TestInput{
				T: 5,
				N: 5,
			},
		},
		{
			name: "schnorr sign session 3x5 success",
			input: testHelper.TestInput{
				T: 3,
				N: 5,
			},
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			keygenShares, err := testHelper.RunSchnorrKeygen(tc.input.T, tc.input.N)

			assert.NoError(t, err)
			assert.NotEmpty(t, keygenShares)

			pk, err := session.SchnorrKeysharePublicKey(keygenShares[0])

			assert.NoError(t, err)
			assert.NotEmpty(t, pk)

			for tr := tc.input.T; tr <= tc.input.N; tr++ {
				msg1 := make([]byte, 32)
				for i := range msg1 {
					msg1[i] = byte(tr)
				}

				// run full DSG using the first 2 key shares
				signs, err := testHelper.RunSchnorrSign(keygenShares[:tr], msg1)

				assert.NoError(t, err)
				assert.NotEmpty(t, signs)

				// and verify signatures
				for _, s := range signs {
					verified := ed25519.Verify(pk, msg1, s)
					assert.True(t, verified)
				}
			}
		})
	}
}
