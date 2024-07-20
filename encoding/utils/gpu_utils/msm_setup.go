//go:build gpu
// +build gpu

package gpu_utils

import (
	"github.com/consensys/gnark-crypto/ecc/bn254"
	bn254_icicle "github.com/ingonyama-zk/icicle/v2/wrappers/golang/curves/bn254"
	bn254_icicle_g2 "github.com/ingonyama-zk/icicle/v2/wrappers/golang/curves/bn254/g2"
)

func SetupMsm(rowsG1 [][]bn254.G1Affine) []bn254_icicle.Affine {
	rowsG1Icicle := make([]bn254_icicle.Affine, 0)

	for _, row := range rowsG1 {
		rowsG1Icicle = append(rowsG1Icicle, BatchConvertGnarkAffineToIcicleAffine(row)...)
	}
	return rowsG1Icicle
}

func SetupMsmG2(heads, trails []bn254.G2Affine) ([]bn254_icicle_g2.G2Affine, []bn254_icicle_g2.G2Affine) {
	headsG2 := make([]bn254_icicle_g2.G2Affine, 0)
	trailsG2 := make([]bn254_icicle_g2.G2Affine, 0)

	headsG2 = BatchConvertGnarkG2AffineToIcicleAffine(heads)
	trailsG2 = BatchConvertGnarkG2AffineToIcicleAffine(trails)

	return headsG2, trailsG2
}
