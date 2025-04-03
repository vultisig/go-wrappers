package session_test

import (
	"testing"

	session "github.com/vultisig/go-wrappers/go-dkls/sessions"
	testHelper "github.com/vultisig/go-wrappers/go-dkls/test"

	"github.com/stretchr/testify/assert"
)

func TestDklsSetup(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name  string
		input testHelper.TestInput
	}{
		{
			name: "dkls setup 2x2 success",
			input: testHelper.TestInput{
				T: 2,
				N: 2,
			},
		},
		{
			name: "dkls setup 2x3 success",
			input: testHelper.TestInput{
				T: 2,
				N: 3,
			},
		},
		{
			name: "dkls setup 3x3 success",
			input: testHelper.TestInput{
				T: 3,
				N: 3,
			},
		},
		{
			name: "dkls setup 3x4 success",
			input: testHelper.TestInput{
				T: 3,
				N: 4,
			},
		},
		{
			name: "dkls setup 4x4 success",
			input: testHelper.TestInput{
				T: 4,
				N: 4,
			},
		},
		{
			name: "dkls setup 4x5 success",
			input: testHelper.TestInput{
				T: 4,
				N: 5,
			},
		},
		{
			name: "dkls setup 5x5 success",
			input: testHelper.TestInput{
				T: 5,
				N: 5,
			},
		},
		{
			name: "dkls setup 3x5 success",
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
			shares, err := testHelper.RunKeygen(tc.input.T, tc.input.N)

			assert.NoError(t, err)
			assert.NotEmpty(t, shares)

			msg := make([]byte, 32)
			for i := range msg {
				msg[i] = 1
			}

			keyID, _ := session.DklsKeyshareKeyID(shares[0])
			ids := testHelper.PrepareIDSlice(tc.input.T)

			setup, _ := session.DklsSignSetupMsgNew(
				keyID,
				nil,
				msg,
				ids,
			)

			// decode key id
			DecodedKeyID, err := session.DklsDecodeKeyID(setup)

			assert.NoError(t, err)
			assert.NotEmpty(t, DecodedKeyID)

			// decode message
			decodedMessage, err := session.DklsDecodeMessage(setup)

			assert.Equal(t, msg, decodedMessage)
			assert.NoError(t, err)
			assert.NotEmpty(t, decodedMessage)

			// decoded party names
			for idx := 0; idx < tc.input.T; idx++ {
				decodedPartyName, err := session.DklsDecodePartyName(setup, idx)

				assert.NoError(t, err)
				assert.NotEmpty(t, decodedPartyName)
			}
		})
	}
}
