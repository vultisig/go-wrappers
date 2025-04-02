package session_test

import (
	"testing"

	session "github.com/vultisig/go-wrapper/go-dkls/sessions"
	testHelper "github.com/vultisig/go-wrapper/go-dkls/test"

	"github.com/stretchr/testify/assert"
)

func TestDklsPresign(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name  string
		input testHelper.TestInput
	}{
		{
			name: "dkls presign 2x2 success",
			input: testHelper.TestInput{
				T: 2,
				N: 2,
			},
		},
		{
			name: "dkls presign 2x3 success",
			input: testHelper.TestInput{
				T: 2,
				N: 3,
			},
		},
		{
			name: "dkls presign 3x3 success",
			input: testHelper.TestInput{
				T: 3,
				N: 3,
			},
		},
		{
			name: "dkls presign 3x4 success",
			input: testHelper.TestInput{
				T: 3,
				N: 4,
			},
		},
		{
			name: "dkls presign 4x4 success",
			input: testHelper.TestInput{
				T: 4,
				N: 4,
			},
		},
		{
			name: "dkls presign 4x5 success",
			input: testHelper.TestInput{
				T: 4,
				N: 5,
			},
		},
		{
			name: "dkls presign 5x5 success",
			input: testHelper.TestInput{
				T: 5,
				N: 5,
			},
		},
		{
			name: "dkls presign 3x5 success",
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

			presignShares, err := testHelper.RunPresign(keygenShares)

			assert.NoError(t, err)
			assert.NotEmpty(t, presignShares)

			for _, s := range presignShares {
				presignHandle, err := session.DklsPresignFromBytes(s)

				assert.NoError(t, err)
				assert.NotEmpty(t, presignHandle)

				presignBytes, err := session.DklsPresignToBytes(presignHandle)

				assert.Equal(t, s, presignBytes)
				assert.NoError(t, err)
				assert.NotEmpty(t, presignBytes)
			}

			handles := make([]session.Handle, 0, len(presignShares))
			for _, s := range presignShares {
				hnd, _ := session.DklsPresignFromBytes(s)
				handles = append(handles, hnd)
			}

			msg := make([]byte, 32)
			for i := range msg {
				msg[i] = 3
			}

			sessionID, err := session.DklsPresignSessionID(handles[0])

			assert.NoError(t, err)
			assert.NotEmpty(t, sessionID)
		})
	}
}
