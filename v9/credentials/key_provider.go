package credentials

import (
	"fmt"

	"github.com/jcmturner/gokrb5/v9/keytab"
	"github.com/jcmturner/gokrb5/v9/types"
)

type KeyProvider interface {
	GetEncryptionKey(types.PrincipalName, string, int, int32) (types.EncryptionKey, int, error)
}

type EncryptionKeyProvider types.EncryptionKey

func (k EncryptionKeyProvider) GetEncryptionKey(pn types.PrincipalName, realm string, kvno int, etype int32) (types.EncryptionKey, int, error) {
	if etype != 0 && etype != k.KeyType {
		return types.EncryptionKey{}, 0, fmt.Errorf("key type does not match: etype: %d, keytype: %d", etype, k.KeyType)
	}
	return types.EncryptionKey(k), 0, nil
}

var (
	_ KeyProvider = EncryptionKeyProvider{}
	_ KeyProvider = (*keytab.Keytab)(nil)
)
