package session_test

import (
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"testing"

	session "github.com/vultisig/go-wrapper/go-dkls/sessions"
	testHelper "github.com/vultisig/go-wrapper/go-dkls/test"

	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/stretchr/testify/assert"
)

func TestDklsSignSessionFlow(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name  string
		input testHelper.TestInput
	}{
		{
			name: "dkls sign session 2x2 success",
			input: testHelper.TestInput{
				T: 2,
				N: 2,
			},
		},
		{
			name: "dkls sign session 2x3 success",
			input: testHelper.TestInput{
				T: 2,
				N: 3,
			},
		},
		{
			name: "dkls sign session 3x3 success",
			input: testHelper.TestInput{
				T: 3,
				N: 3,
			},
		},
		{
			name: "dkls sign session 3x4 success",
			input: testHelper.TestInput{
				T: 3,
				N: 4,
			},
		},
		{
			name: "dkls sign session 4x4 success",
			input: testHelper.TestInput{
				T: 4,
				N: 4,
			},
		},
		{
			name: "dkls sign session 4x5 success",
			input: testHelper.TestInput{
				T: 4,
				N: 5,
			},
		},
		{
			name: "dkls sign session 5x5 success",
			input: testHelper.TestInput{
				T: 5,
				N: 5,
			},
		},
		{
			name: "dkls sign session 3x5 success",
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
			keygenShares, err := testHelper.RunKeygen(tc.input.T, tc.input.N)

			assert.NoError(t, err)
			assert.NotEmpty(t, keygenShares)

			msg := make([]byte, 32)
			for i := range msg {
				msg[i] = 1
			}

			keyID, err := session.DklsKeyshareKeyID(keygenShares[0])

			assert.NoError(t, err)
			assert.NotEmpty(t, keyID)

			msgq := make(map[string][][]byte)
			ids := testHelper.PrepareIDSlice(tc.input.T)

			setup, err := session.DklsSignSetupMsgNew(
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
				sessionHandle, err := session.DklsSignSessionFromSetup(
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
						buf, err := session.DklsSignSessionOutputMessage(party.Session)
						if err != nil {
							t.Logf("WTF")
						}
						assert.NoError(t, err)

						if len(buf) == 0 {
							break
						}

						for idx := 0; idx < tc.input.N; idx++ {
							receiver, err := session.DklsSignSessionMessageReceiver(
								party.Session,
								buf,
								idx,
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
						finished, err := session.DklsSignSessionInputMessage(party.Session, msg)
						assert.NoError(t, err)

						if finished {
							sign, err := session.DklsSignSessionFinish(party.Session)

							assert.NoError(t, err)
							assert.NotEmpty(t, sign)

							shares = append(shares, sign)

							err = session.DklsSignSessionFree(party.Session)
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
			keygenShares, err := testHelper.RunKeygen(tc.input.T, tc.input.N)

			assert.NoError(t, err)
			assert.NotEmpty(t, keygenShares)

			pk, err := session.DklsKeysharePublicKey(keygenShares[0])

			assert.NoError(t, err)
			assert.NotEmpty(t, pk)

			vkX, vkY := secp256k1.DecompressPubkey(pk)
			curve := secp256k1.S256()
			vk := ecdsa.PublicKey{
				Curve: curve,
				X:     vkX,
				Y:     vkY,
			}

			msg1 := make([]byte, 32)
			for i := range msg1 {
				msg1[i] = 1
			}

			// run full DSG using the first N-1 key shares
			signs, err := testHelper.RunSign(keygenShares[:tc.input.N], msg1)

			assert.NoError(t, err)
			assert.NotEmpty(t, signs)

			// and verify signatures
			for _, s := range signs {
				r, s := big.NewInt(0).SetBytes(s[:32]), big.NewInt(0).SetBytes(s[32:64])
				verified := ecdsa.Verify(&vk, msg1, r, s)
				assert.True(t, verified)
			}

			// run pre-sign using key shares from second one to the end
			pre, err := testHelper.RunPresign(keygenShares[1:])

			assert.NoError(t, err)
			assert.NotEmpty(t, pre)

			preHandles := make([]session.Handle, 0, len(pre))

			// convert pre-sign bytes into pre-sign handle object
			for i := 0; i < len(pre); i++ {
				hnd, err := session.DklsPresignFromBytes(pre[i])

				assert.NoError(t, err)
				assert.NotZero(t, hnd)

				preHandles = append(preHandles, hnd)
			}

			msg2 := make([]byte, 32)
			for i := range msg2 {
				msg2[i] = 3
			}

			// calculate the final signature using pre-signs calculated above
			signatures, err := testHelper.RunFinish(preHandles, msg2)

			assert.NoError(t, err)
			assert.NotEmpty(t, signatures)

			// verify signatures
			for _, s := range signatures {
				r, s := big.NewInt(0).SetBytes(s[:32]), big.NewInt(0).SetBytes(s[32:64])
				verified := ecdsa.Verify(&vk, msg2, r, s)
				assert.True(t, verified)
			}
		})
	}
}

func TestSign2x5(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name  string
		input testHelper.TestInput
	}{
		{
			name: "test sign 2x5 success",
			input: testHelper.TestInput{
				T: 2,
				N: 5,
			},
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			keygenShares, err := testHelper.RunKeygen(tc.input.T, tc.input.N)

			assert.NoError(t, err)
			assert.NotEmpty(t, keygenShares)

			pk, err := session.DklsKeysharePublicKey(keygenShares[0])

			assert.NoError(t, err)
			assert.NotEmpty(t, pk)

			vkX, vkY := secp256k1.DecompressPubkey(pk)
			curve := secp256k1.S256()
			vk := ecdsa.PublicKey{
				Curve: curve,
				X:     vkX,
				Y:     vkY,
			}

			for tr := tc.input.T; tr <= tc.input.N; tr++ {
				msg1 := make([]byte, 32)
				for i := range msg1 {
					msg1[i] = byte(tr)
				}

				// run full DSG using the first 2 key shares
				signs, err := testHelper.RunSign(keygenShares[:tr], msg1)

				assert.NoError(t, err)
				assert.NotEmpty(t, signs)

				// and verify signatures
				for _, s := range signs {
					r, s := big.NewInt(0).SetBytes(s[:32]), big.NewInt(0).SetBytes(s[32:64])
					verified := ecdsa.Verify(&vk, msg1, r, s)
					assert.True(t, verified)
				}
			}
		})
	}
}
