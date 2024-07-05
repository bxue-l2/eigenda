package gpu

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/ingonyama-zk/icicle/v2/wrappers/golang/core"
	cr "github.com/ingonyama-zk/icicle/v2/wrappers/golang/cuda_runtime"
	icicle_bn254 "github.com/ingonyama-zk/icicle/v2/wrappers/golang/curves/bn254"
	icicle_bn254_msm "github.com/ingonyama-zk/icicle/v2/wrappers/golang/curves/bn254/msm"
)

func MsmBatchPipelined(rowsFrIcicleCopy core.HostOrDeviceSlice, rowsG1 [][]bn254.G1Affine) (core.HostOrDeviceSlice, error) {
	msmCfg := icicle_bn254_msm.GetDefaultMSMConfig()
	numBatchEle := len(rowsG1)

	rowsG1Icicle := make([]icicle_bn254.Affine, 0)

	fmt.Println("numBatchEle", numBatchEle, len(rowsG1))

	for _, row := range rowsG1 {
		rowsG1Icicle = append(rowsG1Icicle, BatchConvertGnarkAffineToIcicleAffine(row)...)
	}
	rowsG1IcicleCopy := core.HostSliceFromElements[icicle_bn254.Affine](rowsG1Icicle)

	var p icicle_bn254.Projective
	var out core.DeviceSlice

	_, err := out.Malloc(numBatchEle*p.Size(), p.Size())
	if err != cr.CudaSuccess {
		return nil, fmt.Errorf("%v", "Allocating bytes on device for Projective results failed")
	}

	err = icicle_bn254_msm.Msm(rowsFrIcicleCopy, rowsG1IcicleCopy, &msmCfg, out)
	if err != cr.CudaSuccess {
		return nil, fmt.Errorf("%v", "Msm failed")
	}
	return out, nil
}

func MsmBatch(rowsFr [][]fr.Element, rowsG1 [][]bn254.G1Affine) ([]bn254.G1Affine, error) {
	msmCfg := icicle_bn254_msm.GetDefaultMSMConfig()
	numBatchEle := len(rowsFr) // has multiple poly
	rowsSfIcicle := make([]icicle_bn254.ScalarField, 0)
	rowsG1Icicle := make([]icicle_bn254.Affine, 0)

	fmt.Println("numBatchEle", numBatchEle, len(rowsG1))

	for _, row := range rowsFr {
		rowsSfIcicle = append(rowsSfIcicle, ConvertFrToScalarFieldsBytes(row)...)
	}
	rowsFrIcicleCopy := core.HostSliceFromElements[icicle_bn254.ScalarField](rowsSfIcicle)

	for _, row := range rowsG1 {
		rowsG1Icicle = append(rowsG1Icicle, BatchConvertGnarkAffineToIcicleAffine(row)...)
	}
	rowsG1IcicleCopy := core.HostSliceFromElements[icicle_bn254.Affine](rowsG1Icicle)

	var p icicle_bn254.Projective
	var out core.DeviceSlice

	_, err := out.Malloc(numBatchEle*p.Size(), p.Size())
	if err != cr.CudaSuccess {
		return nil, fmt.Errorf("%v", "Allocating bytes on device for Projective results failed")
	}

	err = icicle_bn254_msm.Msm(rowsFrIcicleCopy, rowsG1IcicleCopy, &msmCfg, out)
	if err != cr.CudaSuccess {
		return nil, fmt.Errorf("%v", "Msm failed")
	}

	outHost := make(core.HostSlice[icicle_bn254.Projective], numBatchEle)
	outHost.CopyFromDevice(&out)
	out.Free()

	gnarkOuts := make([]bn254.G1Affine, numBatchEle)
	for i := 0; i < numBatchEle; i++ {
		gnarkOuts[i] = ProjectiveToGnarkAffine(outHost[i])
	}

	return gnarkOuts, nil
}
