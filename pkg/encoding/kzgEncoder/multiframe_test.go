package kzgEncoder

import (
	"testing"

	rs "github.com/Layr-Labs/eigenda/pkg/encoding/encoder"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUniversalVerify(t *testing.T) {
	teardownSuite := setupSuite(t)
	defer teardownSuite(t)

	group, _ := NewKzgEncoderGroup(kzgConfig)
	params := rs.GetEncodingParams(numSys, numPar, uint64(len(GETTYSBURG_ADDRESS_BYTES)))
	enc, err := group.NewKzgEncoder(params)
	require.Nil(t, err)

	numBlob := 5
	samples := make([]Sample, 0)
	for z := 0; z < numBlob; z++ {
		inputFr := rs.ToFrArray(GETTYSBURG_ADDRESS_BYTES)

		commit, _, frames, fIndices, err := enc.Encode(inputFr)
		require.Nil(t, err)

		// create samples
		for i := 0; i < len(frames); i++ {
			f := frames[i]
			j := fIndices[i]

			q, err := rs.GetLeadingCosetIndex(uint64(i), numSys+numPar)
			require.Nil(t, err)

			assert.Equal(t, j, q, "leading coset inconsistency")

			sample = Sample{
				Commitment: commit,
				Proof:      f.Proof,
				Row:        z,
				Coeffs:     f.Coeffs,
				X:          i,
			}
			samples = append(samples, sample)
		}
	}

	assert.True(t, group.UniversalVerify(params, samples, numBlob), "universal batch verification failed\n")
}
