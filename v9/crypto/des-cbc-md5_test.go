package crypto

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDESCBCStringToKey(t *testing.T) {

	et := DesCbcMd5{}

	key, err := et.StringToKey("password", "ATHENA.MIT.EDUraeburn", "")
	if err != nil {
		t.Errorf("error generating key: %v", err)
		return
	}

	assert.Equal(t, hex.EncodeToString(key), "cbc22fae235298e3")
}
