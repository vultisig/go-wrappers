package session_test

import (
	sessions "github.com/vultisig/go-wrappers/go-dkls/sessions"
	testHelper "github.com/vultisig/go-wrappers/go-dkls/test"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestKeyExport(t *testing.T) {
	shares, err := testHelper.RunKeygen(2, 3)
	assert.NoError(t, err)
	assert.NotEmpty(t, shares)

	session, setupMsg, err := sessions.DklsKeyExportReceiverNew(
		shares[0],
		[]string{"p1", "p2", "p3"},
	)
	assert.NoError(t, err)
	assert.NotZero(t, session)
	assert.NotEmpty(t, setupMsg)

	msg1, r1, err := sessions.DklsKeyExporter(shares[1], "p2", setupMsg)
	assert.NoError(t, err)
	assert.Equal(t, "p1", r1)
	assert.NotEmpty(t, msg1)

	msg2, r2, err := sessions.DklsKeyExporter(shares[2], "p3", setupMsg)
	assert.NoError(t, err)
	assert.Equal(t, "p1", r2)
	assert.NotEmpty(t, msg2)

	finished1, err := sessions.DklsKeyExportReceiverInputMessage(session, msg1)
	assert.NoError(t, err)
	assert.False(t, finished1)

	finished2, err := sessions.DklsKeyExportReceiverInputMessage(session, msg2)
	assert.NoError(t, err)
	assert.True(t, finished2)

	secret, err := sessions.DklsKeyExportReceiverFinish(session)
	assert.NoError(t, err)
	assert.NotEmpty(t, secret)
}
