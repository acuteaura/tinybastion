package stabilizer

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestIterativeStabilizer_Iterate(t *testing.T) {
	s := NewIterative[string](2)
	var r []string

	r = s.Iterate(map[string]struct{}{
		"a": {},
		"b": {},
		"c": {},
	})
	assert.ElementsMatch(t, r, []string{})

	r = s.Iterate(map[string]struct{}{
		"a": {},
		"b": {},
		"c": {},
		"d": {},
	})
	assert.ElementsMatch(t, r, []string{"a", "b", "c"})

	r = s.Iterate(map[string]struct{}{
		"b": {},
		"c": {},
		"d": {},
	})
	assert.ElementsMatch(t, r, []string{"b", "c", "d"})

	r = s.Iterate(map[string]struct{}{
		"a": {},
		"b": {},
		"d": {},
	})
	assert.ElementsMatch(t, r, []string{"b", "d"})

	r = s.Iterate(map[string]struct{}{
		"a": {},
		"b": {},
		"d": {},
	})
	assert.ElementsMatch(t, r, []string{"a", "b", "d"})
}
