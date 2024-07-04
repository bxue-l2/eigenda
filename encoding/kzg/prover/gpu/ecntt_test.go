package gpu_test

import (
	"fmt"
	"testing"

	"github.com/Layr-Labs/eigenda/encoding/kzg/prover/gpu"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/stretchr/testify/require"
)

func TestECNTT_GPU(t *testing.T) {
	batch := make([][]bn254.G1Affine, 1)
	batch[0] = make([]bn254.G1Affine, 4096)
	fmt.Println("ECNTT inverse")
	_, err := gpu.ECNtt(batch, true)
	require.Nil(t, err)
}
