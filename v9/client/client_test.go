package client

import (
	"testing"

	"github.com/oiweiwei/gokrb5.fork/v9/config"
	"github.com/oiweiwei/gokrb5.fork/v9/iana/nametype"
	"github.com/oiweiwei/gokrb5.fork/v9/keytab"
	"github.com/oiweiwei/gokrb5.fork/v9/messages"
	"github.com/oiweiwei/gokrb5.fork/v9/types"
	"github.com/stretchr/testify/assert"
)

func TestAssumePreauthentication(t *testing.T) {
	t.Parallel()

	cl := NewWithKeytab("username", "REALM", &keytab.Keytab{}, &config.Config{}, AssumePreAuthentication(true))
	if !cl.settings.assumePreAuthentication {
		t.Fatal("assumePreAuthentication should be true")
	}
	if !cl.settings.AssumePreAuthentication() {
		t.Fatal("AssumePreAuthentication() should be true")
	}
}

func TestAnyServiceClassSPN(t *testing.T) {

	t.Parallel()

	e1 := CacheEntry{
		SPN: "1/cache.entry",
		Ticket: messages.Ticket{
			SName: types.PrincipalName{
				NameType:   nametype.KRB_NT_PRINCIPAL,
				NameString: []string{"1", "cache.entry"},
			},
		},
	}

	cl := &Client{
		cache: &Cache{
			Entries: map[string]CacheEntry{
				"1/cache.entry": e1,
			},
		},
		settings: &Settings{
			anyServiceClassSPN: true,
		},
	}

	for _, testCase := range []struct {
		spn           string
		expected      bool
		expectedEntry CacheEntry
	}{
		{"1/cache.entry", true, e1},
		{"1/cache.entry@REALM", true, e1},
		{"2/cache.entry", true, e1},
		{"2/cache.entry2", false, CacheEntry{}},
	} {
		t.Run(testCase.spn, func(t *testing.T) {
			out, ok := cl.getCacheEntry(testCase.spn)
			assert.Equal(t, testCase.expected, ok, "Expected isAnyServiceClassSPN to match")
			assert.Equal(t, testCase.expectedEntry, out, "Expected cache entry to match for SPN: "+testCase.spn)
		})
	}
}
