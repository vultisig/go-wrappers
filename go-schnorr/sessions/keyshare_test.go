package session_test

import (
	"fmt"
	"testing"

	session "github.com/vultisig/go-wrapper/go-schnorr/sessions"
	testHelper "github.com/vultisig/go-wrapper/go-schnorr/test"

	"github.com/stretchr/testify/assert"
)

func TestSchnorrKeyshare(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name  string
		input testHelper.TestInput
	}{
		{
			name: "schnorr keyshare 2x2 success",
			input: testHelper.TestInput{
				T: 2,
				N: 2,
			},
		},
		{
			name: "schnorr keyshare 2x3 success",
			input: testHelper.TestInput{
				T: 2,
				N: 3,
			},
		},
		{
			name: "schnorr keyshare 3x3 success",
			input: testHelper.TestInput{
				T: 3,
				N: 3,
			},
		},
		{
			name: "schnorr keyshare 3x4 success",
			input: testHelper.TestInput{
				T: 3,
				N: 4,
			},
		},
		{
			name: "schnorr keyshare 4x4 success",
			input: testHelper.TestInput{
				T: 4,
				N: 4,
			},
		},
		{
			name: "schnorr keyshare 4x5 success",
			input: testHelper.TestInput{
				T: 4,
				N: 5,
			},
		},
		{
			name: "schnorr keyshare 5x5 success",
			input: testHelper.TestInput{
				T: 5,
				N: 5,
			},
		},
		{
			name: "schnorr keyshare 3x5 success",
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
			msg := make([]byte, 32)
			for i := range msg {
				msg[i] = 1
			}

			// generate key shares
			shares, err := testHelper.RunSchnorrKeygen(tc.input.T, tc.input.N)

			assert.NoError(t, err)
			assert.NotEmpty(t, shares)

			// key share to bytes
			keyShareBytes, err := session.SchnorrKeyshareToBytes(shares[0])

			assert.NoError(t, err)
			assert.NotEmpty(t, keyShareBytes)

			// key share from bytes
			keyShare, err := session.SchnorrKeyshareFromBytes(keyShareBytes)

			assert.NoError(t, err)
			assert.NotEmpty(t, keyShare)

			// key share public key
			keySharePublicKey, err := session.SchnorrKeysharePublicKey(shares[0])

			assert.NoError(t, err)
			assert.NotEmpty(t, keySharePublicKey)

			// key share key id
			keyID, err := session.SchnorrKeyshareKeyID(shares[0])

			assert.NoError(t, err)
			assert.NotEmpty(t, keyID)

			// chain code

			cc, err := session.SchnorrKeyshareChainCode(shares[0])
			assert.NoError(t, err)
			assert.NotEmpty(t, cc)

			ids := testHelper.PrepareIDSlice(tc.input.T)

			setup, err := session.SchnorrSignSetupMsgNew(
				keyID,
				nil,
				msg,
				ids,
			)

			assert.NoError(t, err)
			assert.NotEmpty(t, setup)

			for i := 1; i <= tc.input.T; i++ {
				id := fmt.Sprintf("p%d", i)
				bytesID := ([]byte)(id)
				sessionHandle, err := session.SchnorrSignSessionFromSetup(
					setup,
					bytesID,
					shares[i-1],
				)

				assert.NoError(t, err)
				assert.NotZero(t, sessionHandle)
			}
		})
	}
}
