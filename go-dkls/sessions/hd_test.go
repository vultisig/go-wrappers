package session_test

import (
	"testing"

	testHelper "github.com/vultisig/go-wrappers/go-dkls/test"

	"github.com/stretchr/testify/assert"
)

func TestDklsHdSessionFlow(t *testing.T) {
	t.Parallel()

	shares, err := testHelper.RunKeygen(2, 3)
	assert.NoError(t, err)
	assert.Len(t, shares, 3)

	const chainPath = "m/44'/60'/0'/0/0"

	derivedShares, err := testHelper.RunHD(t, shares, chainPath)
	assert.NoError(t, err)
	assert.Len(t, derivedShares, len(shares))
}
