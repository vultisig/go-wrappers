package session_test

import (
	"testing"

	sessions "github.com/vultisig/go-wrappers/go-dkls/sessions"
	testHelper "github.com/vultisig/go-wrappers/go-dkls/test"

	"github.com/stretchr/testify/assert"
)

type P = testHelper.Participant

func genPrivateKey() []byte {
	var privateKey [32]byte

	privateKey[0] = 255

	return privateKey[:]
}

func genRootChainCode() []byte {
	rootChain := make([]byte, 32)
	rootChain[0] = 123

	return rootChain
}

func TestKeyImport(t *testing.T) {
	privateKey := genPrivateKey()
	rootChain := genRootChainCode()

	init, setup, err := sessions.DklsKeyImportInitiatorNew(
		privateKey,
		rootChain,
		2,
		[]string{"p1", "p2", "p3"},
	)

	assert.NoError(t, err)
	assert.NotZero(t, init)
	assert.NotEmpty(t, setup)

	importer2, err := sessions.DklsKeyImporter(setup, "p2")
	assert.NoError(t, err)
	assert.NotZero(t, importer2)

	importer3, err := sessions.DklsKeyImporter(setup, "p3")
	assert.NoError(t, err)
	assert.NotZero(t, importer3)

	parties := []P{
		{Session: init, ID: "p1"},
		{Session: importer2, ID: "p2"},
		{Session: importer3, ID: "p3"},
	}

	shares, err := testHelper.RunKeygenLoop(parties)

	assert.NoError(t, err)
	assert.NotZero(t, shares)

	for _, s := range shares {
		code, err := sessions.DklsKeyshareChainCode(s)
		assert.NoError(t, err)
		assert.Equal(t, rootChain, code)
	}
}

func TestKeyImportNoChain(t *testing.T) {
	privateKey := genPrivateKey()

	init, setup, err := sessions.DklsKeyImportInitiatorNew(
		privateKey,
		nil,
		2,
		[]string{"p1", "p2", "p3"},
	)

	assert.NoError(t, err)
	assert.NotZero(t, init)
	assert.NotEmpty(t, setup)

	importer2, err := sessions.DklsKeyImporter(setup, "p2")
	assert.NoError(t, err)
	assert.NotZero(t, importer2)

	importer3, err := sessions.DklsKeyImporter(setup, "p3")
	assert.NoError(t, err)
	assert.NotZero(t, importer3)

	parties := []P{
		{Session: init, ID: "p1"},
		{Session: importer2, ID: "p2"},
		{Session: importer3, ID: "p3"},
	}

	shares, err := testHelper.RunKeygenLoop(parties)

	assert.NoError(t, err)
	assert.NotZero(t, shares)
}
