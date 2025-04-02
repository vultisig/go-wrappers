package session_test

import (
	"testing"

	sessions "github.com/vultisig/go-wrapper/go-schnorr/sessions"
	testHelper "github.com/vultisig/go-wrapper/go-schnorr/test"

	"github.com/stretchr/testify/assert"
)

func TestKeyExport(t *testing.T) {
	shares, err := testHelper.RunSchnorrKeygen(2, 3)

	assert.NoError(t, err)
	assert.NotEmpty(t, shares)

	session, setupMsg, err := sessions.SchnorrKeyExportReceiverNew(
		shares[0],
		[]string{"p1", "p2", "p3"},
	)

	assert.NotZero(t, session)
	assert.NoError(t, err)
	assert.NotEmpty(t, setupMsg)

	msg1, r1, err := sessions.SchnorrKeyExporter(shares[1], "p2", setupMsg)

	assert.NoError(t, err)
	assert.NotEmpty(t, msg1)
	assert.Equal(t, "p1", r1)

	msg2, r2, err := sessions.SchnorrKeyExporter(shares[2], "p3", setupMsg)

	assert.NoError(t, err)
	assert.NotEmpty(t, msg2)
	assert.Equal(t, "p1", r2)

	finished1, err := sessions.SchnorrKeyExportReceiverInputMessage(session, msg1)

	assert.NoError(t, err)
	assert.False(t, finished1)

	finished2, err := sessions.SchnorrKeyExportReceiverInputMessage(session, msg2)

	assert.NoError(t, err)
	assert.True(t, finished2)

	secret, err := sessions.SchnorrKeyExportReceiverFinish(session)

	assert.NoError(t, err)
	assert.NotEmpty(t, secret)
}
