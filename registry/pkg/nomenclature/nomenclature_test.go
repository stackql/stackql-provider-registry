package nomenclature_test

import (
	"testing"

	"gotest.tools/assert"

	. "github.com/stackql/stackql-provider-registry/registry/pkg/nomenclature"
)

func TestProviderTagExtractDefaulted(t *testing.T) {
	d, err := ExtractProviderDesignation("myprovider")

	assert.NilError(t, err)

	assert.Equal(t, d.Name, "myprovider")
	assert.Equal(t, d.Tag, FallbackProviderVersionTag)
	assert.Equal(t, d.Sha, "")
}

func TestProviderTagExtractTagged(t *testing.T) {
	d, err := ExtractProviderDesignation("myprovider:v1")

	assert.NilError(t, err)

	assert.Equal(t, d.Name, "myprovider")
	assert.Equal(t, d.Tag, "v1")
	assert.Equal(t, d.Sha, "")
}

func TestProviderSHAExtract(t *testing.T) {
	d, err := ExtractProviderDesignation("myprovider@someSHA")

	assert.NilError(t, err)

	assert.Equal(t, d.Name, "myprovider")
	assert.Equal(t, d.Tag, "")
	assert.Equal(t, d.Sha, "someSHA")
}

func TestProviderSHAExtractErroneous(t *testing.T) {
	d, err := ExtractProviderDesignation("@myprovider@someSHA")

	assert.Assert(t, err != nil)

	assert.Equal(t, d.Name, "")
	assert.Equal(t, d.Tag, "")
	assert.Equal(t, d.Sha, "")
}

func TestProviderTagExtractErroneous(t *testing.T) {
	d, err := ExtractProviderDesignation(":myprovider:sometag")

	assert.Assert(t, err != nil)

	assert.Equal(t, d.Name, "")
	assert.Equal(t, d.Tag, "")
	assert.Equal(t, d.Sha, "")
}
