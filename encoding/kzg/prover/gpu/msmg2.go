//go:build gpu
// +build gpu

package gpu

import (
	"fmt"

	"github.com/Layr-Labs/eigenda/encoding/utils/gpu_utils"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/ingonyama-zk/icicle/v2/wrappers/golang/core"
	cr "github.com/ingonyama-zk/icicle/v2/wrappers/golang/cuda_runtime"
	icicle_bn254_g2 "github.com/ingonyama-zk/icicle/v2/wrappers/golang/curves/bn254/g2"
	icicle_bn254_msm "github.com/ingonyama-zk/icicle/v2/wrappers/golang/curves/bn254/msm"
)

// MsmBatch function supports batch across blobs.
// totalSize is the number of output points, which equals to numPoly * 2 * dimE , dimE is number of chunks
// currently only accept one blob
func (c *GpuComputeDevice) MsmBatchG2(rowsFrIcicleCopy core.HostOrDeviceSlice, rowsG1Icicle []icicle_bn254_g2.G2Affine) (*bn254.G2Affine, error) {
	msmCfg := icicle_bn254_msm.GetDefaultMSMConfig()

	rowsG1IcicleCopy := core.HostSliceFromElements[icicle_bn254_g2.G2Affine](rowsG1Icicle[:len(rowsG1Icicle)])

	var p icicle_bn254_g2.G2Projective
	var out core.DeviceSlice

	_, err := out.Malloc(p.Size(), p.Size())
	if err != cr.CudaSuccess {
		return nil, fmt.Errorf("%v", "Allocating bytes on device for Projective results failed")
	}

	err = icicle_bn254_g2.G2Msm(rowsFrIcicleCopy, rowsG1IcicleCopy, &msmCfg, out)
	if err != cr.CudaSuccess {
		return nil, fmt.Errorf("%v", "Msm failed")
	}

	outHost := make(core.HostSlice[icicle_bn254_g2.G2Projective], 1)
	outHost.CopyFromDevice(&out)
	out.Free()

	g2Affine := gpu_utils.G2IcicleProjectiveToG2GnarkAffine(outHost[0])

	return &g2Affine, nil
}
