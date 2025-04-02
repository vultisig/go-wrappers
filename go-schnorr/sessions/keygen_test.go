package session_test

import (
	"encoding/hex"
	"fmt"
	"testing"

	dkls_session "github.com/vultisig/go-wrapper/go-dkls/sessions"
	dkls_testHelper "github.com/vultisig/go-wrapper/go-dkls/test"
	session "github.com/vultisig/go-wrapper/go-schnorr/sessions"
	testHelper "github.com/vultisig/go-wrapper/go-schnorr/test"

	"github.com/stretchr/testify/assert"
)

func TestSchnorrKeygenSessionFlow(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name  string
		input testHelper.TestInput
	}{
		{
			name: "schnorr keygen session 2x2 success",
			input: testHelper.TestInput{
				T: 2,
				N: 2,
			},
		},
		{
			name: "schnorr keygen session 2x3 success",
			input: testHelper.TestInput{
				T: 2,
				N: 3,
			},
		},
		{
			name: "schnorr keygen session 3x3 success",
			input: testHelper.TestInput{
				T: 3,
				N: 3,
			},
		},
		{
			name: "schnorr keygen session 3x4 success",
			input: testHelper.TestInput{
				T: 3,
				N: 4,
			},
		},
		{
			name: "schnorr keygen session 4x4 success",
			input: testHelper.TestInput{
				T: 4,
				N: 4,
			},
		},
		{
			name: "schnorr keygen session 4x5 success",
			input: testHelper.TestInput{
				T: 4,
				N: 5,
			},
		},
		{
			name: "schnorr keygen session 5x5 success",
			input: testHelper.TestInput{
				T: 5,
				N: 5,
			},
		},
		{
			name: "schnorr keygen session 3x5 success",
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

			setupMsg, err := session.SchnorrKeygenSetupMsgNew(
				int32(tc.input.T),
				nil,
				ids,
			)

			assert.NoError(t, err)
			assert.NotEmpty(t, setupMsg)

			parties := make([]testHelper.Participant, tc.input.N)

			for i := 1; i <= tc.input.N; i++ {
				id := fmt.Sprintf("p%d", i)
				bytesID := ([]byte)(id)

				sessionHandle, err := session.SchnorrKeygenSessionFromSetup(
					setupMsg,
					bytesID,
				)

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
						buf, err := session.SchnorrKeygenSessionOutputMessage(party.Session)

						assert.NoError(t, err)

						if len(buf) == 0 {
							break
						}
						for idx := 0; idx < tc.input.N; idx++ {
							receiver, err := session.SchnorrKeygenSessionMessageReceiver(
								party.Session,
								buf,
								uint32(idx),
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
						finished, err := session.SchnorrKeygenSessionInputMessage(party.Session, msg)

						assert.NoError(t, err)

						if finished {
							share, err := session.SchnorrKeygenSessionFinish(party.Session)

							assert.NoError(t, err)
							assert.NotZero(t, share)

							shares = append(shares, share)

							err = session.SchnorrKeygenSessionFree(party.Session)

							assert.NoError(t, err)
						}
					}
				}
			}
		})
	}
}

func TestSchnorrKeygenWithDklsSetupMessageFlow(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name  string
		input testHelper.TestInput
	}{
		{
			name: "schnorr keygen with dkls setup message 2x2 success",
			input: testHelper.TestInput{
				T: 2,
				N: 2,
			},
		},
		{
			name: "schnorr keygen with dkls setup message 2x3 success",
			input: testHelper.TestInput{
				T: 2,
				N: 3,
			},
		},
		{
			name: "schnorr keygen with dkls setup message 3x3 success",
			input: testHelper.TestInput{
				T: 3,
				N: 3,
			},
		},
		{
			name: "schnorr keygen with dkls setup message 3x4 success",
			input: testHelper.TestInput{
				T: 3,
				N: 4,
			},
		},
		{
			name: "schnorr keygen with dkls setup message 4x4 success",
			input: testHelper.TestInput{
				T: 4,
				N: 4,
			},
		},
		{
			name: "schnorr keygen with dkls setup message 4x5 success",
			input: testHelper.TestInput{
				T: 4,
				N: 5,
			},
		},
		{
			name: "schnorr keygen with dkls setup message 5x5 success",
			input: testHelper.TestInput{
				T: 5,
				N: 5,
			},
		},
		{
			name: "schnorr keygen with dkls setup message 3x5 success",
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

			setupMsg, err := dkls_session.DklsKeygenSetupMsgNew(
				tc.input.T,
				nil,
				ids,
			)

			assert.NoError(t, err)
			assert.NotEmpty(t, setupMsg)

			parties := make([]testHelper.Participant, tc.input.N)

			for i := 1; i <= tc.input.N; i++ {
				id := fmt.Sprintf("p%d", i)
				bytesID := ([]byte)(id)

				sessionHandle, err := session.SchnorrKeygenSessionFromSetup(
					setupMsg,
					bytesID,
				)

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
						buf, err := session.SchnorrKeygenSessionOutputMessage(party.Session)

						assert.NoError(t, err)

						if len(buf) == 0 {
							break
						}
						for idx := 0; idx < tc.input.N; idx++ {
							receiver, err := session.SchnorrKeygenSessionMessageReceiver(
								party.Session,
								buf,
								uint32(idx),
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
						finished, err := session.SchnorrKeygenSessionInputMessage(party.Session, msg)

						assert.NoError(t, err)

						if finished {
							share, err := session.SchnorrKeygenSessionFinish(party.Session)

							assert.NoError(t, err)
							assert.NotZero(t, share)

							shares = append(shares, share)

							err = session.SchnorrKeygenSessionFree(party.Session)

							assert.NoError(t, err)
						}
					}
				}
			}
		})
	}
}

func TestBothKeygenFlowsWithDklsSetupMessage(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name  string
		input testHelper.TestInput
	}{
		{
			name: "both keygen flows with dkls setup message 2x2 success",
			input: testHelper.TestInput{
				T: 2,
				N: 2,
			},
		},
		{
			name: "both keygen flows with dkls setup message 2x3 success",
			input: testHelper.TestInput{
				T: 2,
				N: 3,
			},
		},
		{
			name: "both keygen flows with dkls setup message 3x3 success",
			input: testHelper.TestInput{
				T: 3,
				N: 3,
			},
		},
		{
			name: "both keygen flows with dkls setup message 3x4 success",
			input: testHelper.TestInput{
				T: 3,
				N: 4,
			},
		},
		{
			name: "both keygen flows with dkls setup message 4x4 success",
			input: testHelper.TestInput{
				T: 4,
				N: 4,
			},
		},
		{
			name: "both keygen flows with dkls setup message 4x5 success",
			input: testHelper.TestInput{
				T: 4,
				N: 5,
			},
		},
		{
			name: "both keygen flows with dkls setup message 5x5 success",
			input: testHelper.TestInput{
				T: 5,
				N: 5,
			},
		},
		{
			name: "both keygen flows with dkls setup message 3x5 success",
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

			// create dkls setup message
			setupMsg, err := dkls_session.DklsKeygenSetupMsgNew(
				tc.input.T,
				nil,
				ids,
			)

			assert.NoError(t, err)
			assert.NotEmpty(t, setupMsg)

			// run dkls flow
			dkls_parties := make([]dkls_testHelper.Participant, tc.input.N)

			for i := 1; i <= tc.input.N; i++ {
				id := fmt.Sprintf("p%d", i)
				bytesID := ([]byte)(id)

				sessionHandle, err := dkls_session.DklsKeygenSessionFromSetup(setupMsg, bytesID)

				assert.NoError(t, err)
				assert.NotZero(t, sessionHandle)

				dkls_parties[i-1] = dkls_testHelper.Participant{
					Session: sessionHandle,
					ID:      id,
				}
			}

			dkls_shares := make([]dkls_session.Handle, 0, tc.input.N)

			for len(dkls_shares) != tc.input.N {
				for _, party := range dkls_parties {
					for {
						buf, err := dkls_session.DklsKeygenSessionOutputMessage(party.Session)

						assert.NoError(t, err)

						if len(buf) == 0 {
							break
						}
						for idx := 0; idx < tc.input.N; idx++ {
							receiver, err := dkls_session.DklsKeygenSessionMessageReceiver(
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

				for _, party := range dkls_parties {
					for _, msg := range msgq[party.ID] {
						finished, err := dkls_session.DklsKeygenSessionInputMessage(party.Session, msg)

						assert.NoError(t, err)

						if finished {
							share, err := dkls_session.DklsKeygenSessionFinish(party.Session)

							assert.NoError(t, err)
							assert.NotZero(t, share)

							dkls_shares = append(dkls_shares, share)

							err = dkls_session.DklsKeygenSessionFree(party.Session)

							assert.NoError(t, err)
						}
					}
				}
			}

			// run schnorr flow
			parties := make([]testHelper.Participant, tc.input.N)

			for i := 1; i <= tc.input.N; i++ {
				id := fmt.Sprintf("p%d", i)
				bytesID := ([]byte)(id)

				sessionHandle, err := session.SchnorrKeygenSessionFromSetup(
					setupMsg,
					bytesID,
				)

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
						buf, err := session.SchnorrKeygenSessionOutputMessage(party.Session)

						assert.NoError(t, err)

						if len(buf) == 0 {
							break
						}
						for idx := 0; idx < tc.input.N; idx++ {
							receiver, err := session.SchnorrKeygenSessionMessageReceiver(
								party.Session,
								buf,
								uint32(idx),
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
						finished, err := session.SchnorrKeygenSessionInputMessage(party.Session, msg)

						assert.NoError(t, err)

						if finished {
							share, err := session.SchnorrKeygenSessionFinish(party.Session)

							assert.NoError(t, err)
							assert.NotZero(t, share)

							shares = append(shares, share)

							err = session.SchnorrKeygenSessionFree(party.Session)

							assert.NoError(t, err)
						}
					}
				}
			}
		})
	}
}

func TestSchnorrKeyRefreshSessionFromSetupFlow(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name  string
		input testHelper.TestInput
	}{
		{
			name: "schnorr key refresh session from setup 2x2 success",
			input: testHelper.TestInput{
				T: 2,
				N: 2,
			},
		},
		{
			name: "schnorr key refresh session from setup 2x3 success",
			input: testHelper.TestInput{
				T: 2,
				N: 3,
			},
		},
		{
			name: "schnorr key refresh session from setup 3x3 success",
			input: testHelper.TestInput{
				T: 3,
				N: 3,
			},
		},
		{
			name: "schnorr key refresh session from setup 3x4 success",
			input: testHelper.TestInput{
				T: 3,
				N: 4,
			},
		},
		{
			name: "schnorr key refresh session from setup 4x4 success",
			input: testHelper.TestInput{
				T: 4,
				N: 4,
			},
		},
		{
			name: "schnorr key refresh session from setup 4x5 success",
			input: testHelper.TestInput{
				T: 4,
				N: 5,
			},
		},
		{
			name: "schnorr key refresh session from setup 5x5 success",
			input: testHelper.TestInput{
				T: 5,
				N: 5,
			},
		},
		{
			name: "schnorr key refresh session from setup 3x5 success",
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
			oldShares, err := testHelper.RunSchnorrKeygen(tc.input.T, tc.input.N)

			assert.NoError(t, err)
			assert.NotEmpty(t, oldShares)

			msgq := make(map[string][][]byte)
			ids := testHelper.PrepareIDSlice(tc.input.N)
			keyID, err := session.SchnorrKeyshareKeyID(oldShares[0])

			assert.NoError(t, err)
			assert.NotEmpty(t, keyID)

			// cc, err := session.SchnorrKeyshareChainCode(oldShares[0])
			// assert.NoError(t, err)
			// assert.NotEmpty(t, cc)

			parties := make([]testHelper.Participant, 0, tc.input.N)

			setup, err := session.SchnorrKeygenSetupMsgNew(int32(tc.input.T), keyID, ids)

			assert.NoError(t, err)
			assert.NotEmpty(t, setup)

			for partyID, share := range oldShares {
				id := fmt.Sprintf("p%d", partyID+1)

				sessionHnd, err := session.SchnorrKeyRefreshSessionFromSetup(
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
						buf, err := session.SchnorrKeygenSessionOutputMessage(party.Session)

						assert.NoError(t, err)

						if len(buf) == 0 {
							break
						}
						for idx := 0; idx < tc.input.N; idx++ {
							receiver, err := session.SchnorrKeygenSessionMessageReceiver(
								party.Session,
								buf,
								uint32(idx),
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
						finished, err := session.SchnorrKeygenSessionInputMessage(party.Session, msg)

						assert.NoError(t, err)

						if finished {
							share, err := session.SchnorrKeygenSessionFinish(party.Session)

							assert.NoError(t, err)
							assert.NotZero(t, share)

							shares = append(shares, share)

							err = session.SchnorrKeygenSessionFree(party.Session)

							assert.NoError(t, err)
						}
					}
				}
			}
		})
	}
}
func hexToLittleEndianBytes(hexStr string) ([]byte, error) {
	// 1. First decode the hex string to bytes
	bytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, err
	}

	// 2. Reverse the bytes to get little endian
	// Since we're working with a 32-byte value, we need to reverse the whole array
	for i := 0; i < len(bytes)/2; i++ {
		bytes[i], bytes[len(bytes)-1-i] = bytes[len(bytes)-1-i], bytes[i]
	}

	return bytes, nil
}
func TestSchnorrKeyMigrateSessionFromSetupFlow(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name  string
		input testHelper.TestInput
	}{

		{
			name: "schnorr key migrate session from setup 2x3 success",
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
			oldShares, err := testHelper.RunSchnorrKeygen(tc.input.T, tc.input.N)

			assert.NoError(t, err)
			assert.NotEmpty(t, oldShares)

			msgq := make(map[string][][]byte)
			ids := testHelper.PrepareIDSlice(tc.input.N)
			keyID, err := session.SchnorrKeyshareKeyID(oldShares[0])

			assert.NoError(t, err)
			assert.NotEmpty(t, keyID)

			parties := make([]testHelper.Participant, 0, tc.input.N)

			setup, err := session.SchnorrKeygenSetupMsgNew(int32(tc.input.T), keyID, ids)

			assert.NoError(t, err)
			assert.NotEmpty(t, setup)

			publickey, err := hex.DecodeString("8113efb1ac98de9349353f8b334a7fb5bc91fef89717fd04039e7c7834ccdf28")
			rootchain := []byte{1, 0, 2, 3, 4, 5, 6, 7, 8, 9, 1, 0, 2, 3, 4, 5, 6, 7, 8, 9, 1, 0, 2, 3, 4, 5, 6, 7, 8, 9, 1, 2}

			ui := make([][]byte, 3)
			ui[0], err = hexToLittleEndianBytes("085ef3eccbf17cda605ac888e2a2b5c87b26d9864511d68df998dec727220464")
			ui[1], err = hexToLittleEndianBytes("013cce1a07f93b0e1cb008521c1ab55c232b18649e3b0a67b6b6e77e1e2cd8f4")
			ui[2], err = hexToLittleEndianBytes("06057b0b8bbfb943330de183d9da76a2ada29e0b172819b858b59f019cecdd6b")

			for partyID := range 3 {
				id := fmt.Sprintf("p%d", partyID+1)

				sessionHnd, err := session.SchnorrKeyMigrateSessionFromSetup(
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
						buf, err := session.SchnorrKeygenSessionOutputMessage(party.Session)

						assert.NoError(t, err)

						if len(buf) == 0 {
							break
						}
						for idx := 0; idx < tc.input.N; idx++ {
							receiver, err := session.SchnorrKeygenSessionMessageReceiver(
								party.Session,
								buf,
								uint32(idx),
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
						finished, err := session.SchnorrKeygenSessionInputMessage(party.Session, msg)

						assert.NoError(t, err)

						if finished {
							share, err := session.SchnorrKeygenSessionFinish(party.Session)

							assert.NoError(t, err)
							assert.NotZero(t, share)

							shares = append(shares, share)

							err = session.SchnorrKeygenSessionFree(party.Session)

							assert.NoError(t, err)
						}
					}
				}
			}
		})
	}
}
