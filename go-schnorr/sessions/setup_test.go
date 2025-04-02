package session_test

import (
	"testing"

	session "github.com/vultisig/go-wrapper/go-schnorr/sessions"
	testHelper "github.com/vultisig/go-wrapper/go-schnorr/test"

	"github.com/stretchr/testify/assert"
)

func TestSchnorrSetup(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name  string
		input testHelper.TestInput
	}{
		{
			name: "schnorr setup 2x2 success",
			input: testHelper.TestInput{
				T: 2,
				N: 2,
			},
		},
		{
			name: "schnorr setup 2x3 success",
			input: testHelper.TestInput{
				T: 2,
				N: 3,
			},
		},
		{
			name: "schnorr setup 3x3 success",
			input: testHelper.TestInput{
				T: 3,
				N: 3,
			},
		},
		{
			name: "schnorr setup 3x4 success",
			input: testHelper.TestInput{
				T: 3,
				N: 4,
			},
		},
		{
			name: "schnorr setup 4x4 success",
			input: testHelper.TestInput{
				T: 4,
				N: 4,
			},
		},
		{
			name: "schnorr setup 4x5 success",
			input: testHelper.TestInput{
				T: 4,
				N: 5,
			},
		},
		{
			name: "schnorr setup 5x5 success",
			input: testHelper.TestInput{
				T: 5,
				N: 5,
			},
		},
		{
			name: "schnorr setup 3x5 success",
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
			shares, err := testHelper.RunSchnorrKeygen(tc.input.T, tc.input.N)

			assert.NoError(t, err)
			assert.NotEmpty(t, shares)

			msg := make([]byte, 32)
			for i := range msg {
				msg[i] = 1
			}

			keyID, _ := session.SchnorrKeyshareKeyID(shares[0])
			ids := testHelper.PrepareIDSlice(tc.input.T)

			setup, _ := session.SchnorrSignSetupMsgNew(
				keyID,
				nil,
				msg,
				ids,
			)

			// decode key id
			decodedKeyID, err := session.SchnorrDecodeKeyID(setup)

			assert.NoError(t, err)
			assert.NotEmpty(t, decodedKeyID)

			// decode session id
			decodedSessionID, err := session.SchnorrDecodeSessionID(setup)

			assert.NoError(t, err)
			assert.NotEmpty(t, decodedSessionID)

			// decode message
			decodedMessage, err := session.SchnorrDecodeMessage(setup)

			assert.Equal(t, msg, decodedMessage)
			assert.NoError(t, err)
			assert.NotEmpty(t, decodedMessage)

			// decoded party names
			for idx := 0; idx < tc.input.T; idx++ {
				decodedPartyName, err := session.SchnorrDecodePartyName(setup, idx)

				assert.NoError(t, err)
				assert.NotEmpty(t, decodedPartyName)
			}
		})
	}
}
