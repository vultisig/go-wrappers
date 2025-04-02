package session_test

import (
	"encoding/hex"
	"fmt"
	"testing"

	session "github.com/vultisig/go-wrapper/go-dkls/sessions"
	testHelper "github.com/vultisig/go-wrapper/go-dkls/test"
	schnorr_session "github.com/vultisig/go-wrapper/go-schnorr/sessions"

	"github.com/stretchr/testify/assert"
)

func TestDklsKeygenSessionFlow(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name  string
		input testHelper.TestInput
	}{
		{
			name: "dkls keygen session 2x2 success",
			input: testHelper.TestInput{
				T: 2,
				N: 2,
			},
		},
		{
			name: "dkls keygen session 2x3 success",
			input: testHelper.TestInput{
				T: 2,
				N: 3,
			},
		},
		{
			name: "dkls keygen session 3x3 success",
			input: testHelper.TestInput{
				T: 3,
				N: 3,
			},
		},
		{
			name: "dkls keygen session 3x4 success",
			input: testHelper.TestInput{
				T: 3,
				N: 4,
			},
		},
		{
			name: "dkls keygen session 4x4 success",
			input: testHelper.TestInput{
				T: 4,
				N: 4,
			},
		},
		{
			name: "dkls keygen session 4x5 success",
			input: testHelper.TestInput{
				T: 4,
				N: 5,
			},
		},
		{
			name: "dkls keygen session 5x5 success",
			input: testHelper.TestInput{
				T: 5,
				N: 5,
			},
		},
		{
			name: "dkls keygen session 3x5 success",
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
			msgq := make(map[string][][]byte)
			ids := testHelper.PrepareIDSlice(tc.input.N)
			setupMsg, err := session.DklsKeygenSetupMsgNew(tc.input.T, nil, ids)

			assert.NoError(t, err)
			assert.NotEmpty(t, setupMsg)

			parties := make([]testHelper.Participant, tc.input.N)

			for i := 1; i <= tc.input.N; i++ {
				id := fmt.Sprintf("p%d", i)
				bytesID := ([]byte)(id)

				sessionHandle, err := session.DklsKeygenSessionFromSetup(setupMsg, bytesID)

				assert.NoError(t, err)
				assert.NotZero(t, sessionHandle)

				parties[i-1] = testHelper.Participant{
					Session: sessionHandle,
					ID:      id,
				}
			}

			shares := make([]session.Handle, 0, tc.input.N)

			for len(shares) != tc.input.N {
				for _, party := range parties {
					for {
						buf, err := session.DklsKeygenSessionOutputMessage(party.Session)

						assert.NoError(t, err)

						if len(buf) == 0 {
							break
						}
						for idx := 0; idx < tc.input.N; idx++ {
							receiver, err := session.DklsKeygenSessionMessageReceiver(
								party.Session,
								buf,
								idx,
							)

							assert.NoError(t, err)

							if receiver == "" {
								break
							}

							msgq[receiver] = append(msgq[receiver], buf)
						}
					}
				}

				for _, party := range parties {
					for _, msg := range msgq[party.ID] {
						finished, err := session.DklsKeygenSessionInputMessage(party.Session, msg)

						assert.NoError(t, err)

						if finished {
							share, err := session.DklsKeygenSessionFinish(party.Session)

							assert.NoError(t, err)
							assert.NotZero(t, share)

							shares = append(shares, share)

							err = session.DklsKeygenSessionFree(party.Session)

							assert.NoError(t, err)
						}
					}
				}
			}
		})
	}
}

func TestDklsKeygenWithSchnorrSetupMessageFlow(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name  string
		input testHelper.TestInput
	}{
		{
			name: "dkls keygen with shnorr setup msg 2x2 success",
			input: testHelper.TestInput{
				T: 2,
				N: 2,
			},
		},
		{
			name: "dkls keygen with shnorr setup msg 2x3 success",
			input: testHelper.TestInput{
				T: 2,
				N: 3,
			},
		},
		{
			name: "dkls keygen with shnorr setup msg 3x3 success",
			input: testHelper.TestInput{
				T: 3,
				N: 3,
			},
		},
		{
			name: "dkls keygen with shnorr setup msg 3x4 success",
			input: testHelper.TestInput{
				T: 3,
				N: 4,
			},
		},
		{
			name: "dkls keygen with shnorr setup msg 4x4 success",
			input: testHelper.TestInput{
				T: 4,
				N: 4,
			},
		},
		{
			name: "dkls keygen with shnorr setup msg 4x5 success",
			input: testHelper.TestInput{
				T: 4,
				N: 5,
			},
		},
		{
			name: "dkls keygen with shnorr setup msg 5x5 success",
			input: testHelper.TestInput{
				T: 5,
				N: 5,
			},
		},
		{
			name: "dkls keygen with shnorr setup msg 3x5 success",
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
			msgq := make(map[string][][]byte)
			ids := testHelper.PrepareIDSlice(tc.input.N)
			setupMsg, err := schnorr_session.SchnorrKeygenSetupMsgNew(int32(tc.input.T), nil, ids)

			assert.NoError(t, err)
			assert.NotEmpty(t, setupMsg)

			parties := make([]testHelper.Participant, tc.input.N)

			for i := 1; i <= tc.input.N; i++ {
				id := fmt.Sprintf("p%d", i)
				bytesID := ([]byte)(id)

				sessionHandle, err := session.DklsKeygenSessionFromSetup(setupMsg, bytesID)

				assert.NoError(t, err)
				assert.NotZero(t, sessionHandle)

				parties[i-1] = testHelper.Participant{
					Session: sessionHandle,
					ID:      id,
				}
			}

			shares := make([]session.Handle, 0, tc.input.N)

			for len(shares) != tc.input.N {
				for _, party := range parties {
					for {
						buf, err := session.DklsKeygenSessionOutputMessage(party.Session)

						assert.NoError(t, err)

						if len(buf) == 0 {
							break
						}
						for idx := 0; idx < tc.input.N; idx++ {
							receiver, err := session.DklsKeygenSessionMessageReceiver(
								party.Session,
								buf,
								idx,
							)

							assert.NoError(t, err)

							if receiver == "" {
								break
							}

							msgq[receiver] = append(msgq[receiver], buf)
						}
					}
				}

				for _, party := range parties {
					for _, msg := range msgq[party.ID] {
						finished, err := session.DklsKeygenSessionInputMessage(party.Session, msg)

						assert.NoError(t, err)

						if finished {
							share, err := session.DklsKeygenSessionFinish(party.Session)

							assert.NoError(t, err)
							assert.NotZero(t, share)

							shares = append(shares, share)

							err = session.DklsKeygenSessionFree(party.Session)

							assert.NoError(t, err)
						}
					}
				}
			}
		})
	}
}

func TestDklsKeyRefreshSessionFromSetupFlow(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name  string
		input testHelper.TestInput
	}{
		{
			name: "dkls key refresh session from setup 2x2 success",
			input: testHelper.TestInput{
				T: 2,
				N: 2,
			},
		},
		{
			name: "dkls key refresh session from setup 2x3 success",
			input: testHelper.TestInput{
				T: 2,
				N: 3,
			},
		},
		{
			name: "dkls key refresh session from setup 3x3 success",
			input: testHelper.TestInput{
				T: 3,
				N: 3,
			},
		},
		{
			name: "dkls key refresh session from setup 3x4 success",
			input: testHelper.TestInput{
				T: 3,
				N: 4,
			},
		},
		{
			name: "dkls key refresh session from setup 4x4 success",
			input: testHelper.TestInput{
				T: 4,
				N: 4,
			},
		},
		{
			name: "dkls key refresh session from setup 4x5 success",
			input: testHelper.TestInput{
				T: 4,
				N: 5,
			},
		},
		{
			name: "dkls key refresh session from setup 5x5 success",
			input: testHelper.TestInput{
				T: 5,
				N: 5,
			},
		},
		{
			name: "dkls key refresh session from setup 3x5 success",
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
			oldShares, err := testHelper.RunKeygen(tc.input.T, tc.input.N)

			assert.NoError(t, err)
			assert.NotEmpty(t, oldShares)

			msgq := make(map[string][][]byte)
			ids := testHelper.PrepareIDSlice(tc.input.N)
			keyID, err := session.DklsKeyshareKeyID(oldShares[0])

			assert.NoError(t, err)
			assert.NotEmpty(t, keyID)

			cc, err := session.DklsKeyshareChainCode(oldShares[0])
			assert.NoError(t, err)
			assert.NotEmpty(t, cc)

			parties := make([]testHelper.Participant, 0, tc.input.N)

			setup, err := session.DklsKeygenSetupMsgNew(
				tc.input.T,
				keyID,
				ids,
			)

			assert.NoError(t, err)
			assert.NotEmpty(t, setup)

			for partyID, share := range oldShares {
				id := fmt.Sprintf("p%d", partyID+1)

				sessionHnd, err := session.DklsKeyRefreshSessionFromSetup(
					setup,
					([]byte)(id),
					share,
				)

				assert.NoError(t, err)
				assert.NotZero(t, sessionHnd)

				parties = append(
					parties,
					testHelper.Participant{
						Session: sessionHnd,
						ID:      id,
					},
				)
			}

			shares := make([]session.Handle, 0, tc.input.N)

			for len(shares) != tc.input.N {
				for _, party := range parties {
					for {
						buf, err := session.DklsKeygenSessionOutputMessage(party.Session)

						assert.NoError(t, err)

						if len(buf) == 0 {
							break
						}
						for idx := 0; idx < tc.input.N; idx++ {
							receiver, err := session.DklsKeygenSessionMessageReceiver(
								party.Session,
								buf,
								idx,
							)

							assert.NoError(t, err)

							if receiver == "" {
								break
							}

							msgq[receiver] = append(msgq[receiver], buf)
						}
					}
				}

				for _, party := range parties {
					for _, msg := range msgq[party.ID] {
						finished, err := session.DklsKeygenSessionInputMessage(party.Session, msg)

						assert.NoError(t, err)

						if finished {
							share, err := session.DklsKeygenSessionFinish(party.Session)

							assert.NoError(t, err)
							assert.NotZero(t, share)

							shares = append(shares, share)

							err = session.DklsKeygenSessionFree(party.Session)

							assert.NoError(t, err)
						}
					}
				}
			}
		})
	}
}

func TestDklsKeyMigrateSessionFromSetupFlow(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name  string
		input testHelper.TestInput
	}{

		{
			name: "dkls key refresh session from setup 2x3 success",
			input: testHelper.TestInput{
				T: 2,
				N: 3,
			},
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			oldShares, err := testHelper.RunKeygen(tc.input.T, tc.input.N)

			assert.NoError(t, err)
			assert.NotEmpty(t, oldShares)

			msgq := make(map[string][][]byte)
			ids := testHelper.PrepareIDSlice(tc.input.N)
			keyID, err := session.DklsKeyshareKeyID(oldShares[0])

			assert.NoError(t, err)
			assert.NotEmpty(t, keyID)

			// 			cc, err := session.DklsKeyshareChainCode(oldShares[0])
			// 			assert.NoError(t, err)
			// 			assert.NotEmpty(t, cc)

			parties := make([]testHelper.Participant, 0, tc.input.N)

			setup, err := session.DklsKeygenSetupMsgNew(
				tc.input.T,
				keyID,
				ids,
			)

			assert.NoError(t, err)
			assert.NotEmpty(t, setup)

			publickey, err := hex.DecodeString("02eba32793892022121314aed023df242292d313cb657f6f69016d90b6cfc92d33")
			rootchain := []byte{1, 0, 2, 3, 4, 5, 6, 7, 8, 9, 1, 0, 2, 3, 4, 5, 6, 7, 8, 9, 1, 0, 2, 3, 4, 5, 6, 7, 8, 9, 1, 2}

			ui := make([][]byte, 3)
			ui[0], err = hex.DecodeString("3B6661CC3A28C174AF9D0FDD966E9F9D9D2A96682A504E1E9165D700BDC47809")
			ui[1], err = hex.DecodeString("3361D26EBB452DDA716E38F20405B42E3ABDC890CAEE1150AB0D019D45091DC4")
			ui[2], err = hex.DecodeString("71FDD4E9358DB270FA0EF15F4D72A6267B012781D154D2A380ECFCA86E85BEA2")

			for partyID := range 3 {
				id := fmt.Sprintf("p%d", partyID+1)

				sessionHnd, err := session.DklsKeyMigrateSessionFromSetup(
					setup,
					([]byte)(id),
					publickey,
					rootchain,
					ui[partyID],
				)

				assert.NoError(t, err)
				assert.NotZero(t, sessionHnd)

				parties = append(
					parties,
					testHelper.Participant{
						Session: sessionHnd,
						ID:      id,
					},
				)
			}

			shares := make([]session.Handle, 0, tc.input.N)

			for len(shares) != tc.input.N {
				for _, party := range parties {
					for {
						buf, err := session.DklsKeygenSessionOutputMessage(party.Session)

						assert.NoError(t, err)

						if len(buf) == 0 {
							break
						}
						for idx := 0; idx < tc.input.N; idx++ {
							receiver, err := session.DklsKeygenSessionMessageReceiver(
								party.Session,
								buf,
								idx,
							)

							assert.NoError(t, err)

							if receiver == "" {
								break
							}

							msgq[receiver] = append(msgq[receiver], buf)
						}
					}
				}

				for _, party := range parties {
					for _, msg := range msgq[party.ID] {
						finished, err := session.DklsKeygenSessionInputMessage(party.Session, msg)

						assert.NoError(t, err)

						if finished {
							share, err := session.DklsKeygenSessionFinish(party.Session)

							assert.NoError(t, err)
							assert.NotZero(t, share)

							shares = append(shares, share)

							err = session.DklsKeygenSessionFree(party.Session)

							assert.NoError(t, err)
						}
					}
				}
			}
		})
	}
}
