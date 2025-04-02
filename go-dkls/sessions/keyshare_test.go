package session_test

import (
	"fmt"
	"testing"

	session "github.com/vultisig/go-wrapper/go-dkls/sessions"
	testHelper "github.com/vultisig/go-wrapper/go-dkls/test"

	"github.com/stretchr/testify/assert"
)

func TestDklsKeyshare(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name  string
		input testHelper.TestInput
	}{
		{
			name: "dkls keyshare 2x2 success",
			input: testHelper.TestInput{
				T: 2,
				N: 2,
			},
		},
		{
			name: "dkls keyshare 2x3 success",
			input: testHelper.TestInput{
				T: 2,
				N: 3,
			},
		},
		{
			name: "dkls keyshare 3x3 success",
			input: testHelper.TestInput{
				T: 3,
				N: 3,
			},
		},
		{
			name: "dkls keyshare 3x4 success",
			input: testHelper.TestInput{
				T: 3,
				N: 4,
			},
		},
		{
			name: "dkls keyshare 4x4 success",
			input: testHelper.TestInput{
				T: 4,
				N: 4,
			},
		},
		{
			name: "dkls keyshare 4x5 success",
			input: testHelper.TestInput{
				T: 4,
				N: 5,
			},
		},
		{
			name: "dkls keyshare 5x5 success",
			input: testHelper.TestInput{
				T: 5,
				N: 5,
			},
		},
		{
			name: "dkls keyshare 3x5 success",
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
			shares, err := testHelper.RunKeygen(tc.input.T, tc.input.N)

			assert.NoError(t, err)
			assert.NotEmpty(t, shares)

			// key share to bytes
			keyShareBytes, err := session.DklsKeyshareToBytes(shares[0])

			assert.NoError(t, err)
			assert.NotEmpty(t, keyShareBytes)

			// key share from bytes
			keyShare, err := session.DklsKeyshareFromBytes(keyShareBytes)

			assert.NoError(t, err)
			assert.NotEmpty(t, keyShare)

			// key share public key
			keySharePublicKey, err := session.DklsKeysharePublicKey(shares[0])

			assert.NoError(t, err)
			assert.NotEmpty(t, keySharePublicKey)

			// key share key id
			keyID, err := session.DklsKeyshareKeyID(shares[0])

			assert.NoError(t, err)
			assert.NotEmpty(t, keyID)

			// key share to refresh bytes
			keyShareToRefreshBytes, err := session.DklsKeyshareToRefreshBytes(shares[0])

			assert.NoError(t, err)
			assert.NotEmpty(t, keyShareToRefreshBytes)

			// derive child1 public key
			derivedChildPublicKey, err := session.DklsKeyshareDeriveChildPublicKey(shares[0], []byte("m"))

			assert.NoError(t, err)
			assert.NotEmpty(t, derivedChildPublicKey)

			// derive child2 public key
			derivedChildPublicKey2, err := session.DklsKeyshareDeriveChildPublicKey(shares[0], []byte("m/0/1/42"))

			assert.NoError(t, err)
			assert.NotEmpty(t, derivedChildPublicKey2)

			ids := testHelper.PrepareIDSlice(tc.input.T)

			setup, err := session.DklsSignSetupMsgNew(
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
				sessionHandle, err := session.DklsSignSessionFromSetup(
					setup,
					bytesID,
					shares[i-1],
				)

				assert.NoError(t, err)
				assert.NotZero(t, sessionHandle)
			}
			for _, share := range shares {
				err := session.DklsKeyshareFree(share)

				assert.NoError(t, err)
			}
		})
	}
}
