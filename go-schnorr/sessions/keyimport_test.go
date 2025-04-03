package session_test

import (
	"testing"

	sessions "github.com/vultisig/go-wrappers/go-schnorr/sessions"
	testHelper "github.com/vultisig/go-wrappers/go-schnorr/test"

	"github.com/stretchr/testify/assert"
)

type P = testHelper.Participant

func genPrivateKey() []byte {
	var privateKey [32]byte

	privateKey[0] = 255

	return privateKey[:]
}

func TestKeyImport(t *testing.T) {
	privateKey := genPrivateKey()

	init, setup, err := sessions.SchnorrKeyImportInitiatorNew(privateKey, nil, 2, []string{"p1", "p2", "p3"})

	assert.NoError(t, err)
	assert.NotZero(t, init)
	assert.NotEmpty(t, setup)

	importer2, err := sessions.SchnorrKeyImporterNew(setup, "p2")

	assert.NoError(t, err)
	assert.NotZero(t, importer2)

	importer3, err := sessions.SchnorrKeyImporterNew(setup, "p3")

	assert.NoError(t, err)
	assert.NotZero(t, importer3)

	parties := []P{
		{Session: init, ID: "p1"},
		{Session: importer2, ID: "p2"},
		{Session: importer3, ID: "p3"},
	}

	shares, err := testHelper.RunSchnorrKeygenLoop(parties)

	assert.NoError(t, err)
	assert.NotEmpty(t, shares)
}
