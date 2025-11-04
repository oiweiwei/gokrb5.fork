package types

import (
	"github.com/oiweiwei/gokrb5.fork/v9/iana/nametype"
	"github.com/stretchr/testify/assert"

	"testing"
)

func TestPrincipalName_GetSalt(t *testing.T) {
	t.Parallel()
	pn := PrincipalName{
		NameType:   1,
		NameString: []string{"firststring", "secondstring"},
	}
	assert.Equal(t, "TEST.GOKRB5firststringsecondstring", pn.GetSalt("TEST.GOKRB5"), "Principal name default salt not as expected")
}

func TestPrincipalName_EqualHostName(t *testing.T) {

	t.Parallel()

	for _, tc := range []struct {
		pn1, pn2 PrincipalName
		expected bool
	}{
		{
			pn1:      PrincipalName{NameString: []string{"HTTP", "host.example.com"}},
			pn2:      PrincipalName{NameString: []string{"CIFS", "host.example.com"}},
			expected: true,
		},
		{
			pn1:      PrincipalName{NameString: []string{"HTTP", "host.example.com"}},
			pn2:      PrincipalName{NameString: []string{"HTTP", "otherhost.example.com"}},
			expected: false,
		},
		{
			pn1:      PrincipalName{NameString: []string{"HTTP", "host.example.com"}},
			pn2:      PrincipalName{NameString: []string{"HTTP", "HOST.EXAMPLE.COM"}},
			expected: true,
		},
	} {
		result := tc.pn1.EqualHostName(tc.pn2)
		assert.Equal(t, tc.expected, result, "PrincipalName EqualHostName result not as expected")
	}

}

func TestParseSPNString(t *testing.T) {
	pn, realm := ParseSPNString("HTTP/www.example.com@REALM.COM")
	assert.Equal(t, "REALM.COM", realm, "realm value not as expected")
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, pn.NameType, "name type not as expected")
	assert.Equal(t, "HTTP", pn.NameString[0], "first element of name string not as expected")
	assert.Equal(t, "www.example.com", pn.NameString[1], "second element of name string not as expected")

	pn, realm = ParseSPNString("HTTP/www.example.com")
	assert.Equal(t, "", realm, "realm value not as expected")
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, pn.NameType, "name type not as expected")
	assert.Equal(t, "HTTP", pn.NameString[0], "first element of name string not as expected")
	assert.Equal(t, "www.example.com", pn.NameString[1], "second element of name string not as expected")

	pn, realm = ParseSPNString("www.example.com@REALM.COM")
	assert.Equal(t, "REALM.COM", realm, "realm value not as expected")
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, pn.NameType, "name type not as expected")
	assert.Equal(t, "www.example.com", pn.NameString[0], "second element of name string not as expected")

}
