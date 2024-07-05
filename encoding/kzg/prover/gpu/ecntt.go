package gpu

import (
	"fmt"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
	icicle_bn254 "github.com/ingonyama-zk/icicle/v2/wrappers/golang/curves/bn254"
	ecntt "github.com/ingonyama-zk/icicle/v2/wrappers/golang/curves/bn254/ecntt"
	icicle_bn254_ntt "github.com/ingonyama-zk/icicle/v2/wrappers/golang/curves/bn254/ntt"

	"github.com/ingonyama-zk/icicle/v2/wrappers/golang/core"
)

func setupEcntt(numSymbol int, batchSize int) core.NTTConfig[[icicle_bn254.SCALAR_LIMBS]uint32] {
	cfg := icicle_bn254_ntt.GetDefaultNttConfig()

	cfg.Ordering = core.KNN
	cfg.NttAlgorithm = core.Auto

	cfg.BatchSize = int32(batchSize)

	exp := int32(20) //int32(math.Ceil(math.Log2(float64(numSymbol))))

	fmt.Println("cfg.BatchSize", cfg.BatchSize, "exp", exp)

	rouMont, _ := fft.Generator(uint64(1 << 20))
	rou := rouMont.Bits()
	rouIcicle := icicle_bn254.ScalarField{}

	limbs := core.ConvertUint64ArrToUint32Arr(rou[:])

	rouIcicle.FromLimbs(limbs)
	fmt.Println("rouIcicle", rouIcicle)

	initDomainStart := time.Now()
	icicle_bn254_ntt.InitDomain(rouIcicle, cfg.Ctx, false)
	fmt.Println("init domain takes", time.Since(initDomainStart))
	return cfg
}

func ECNttPipeplined(pointsIcileProjective core.HostOrDeviceSlice, numSymbol int, batchSize int, isInverse bool) (core.HostOrDeviceSlice, error) {
	cfg := setupEcntt(numSymbol, batchSize)

	totalNumSym := cfg.BatchSize * int32(numSymbol)

	output := make(core.HostSlice[icicle_bn254.Projective], int(totalNumSym))
	fmt.Println("totalNumSym", totalNumSym)

	start := time.Now()

	if isInverse {
		e := ecntt.ECNtt(pointsIcileProjective, core.KInverse, &cfg, output)
		fmt.Println("IcicleErrorCode", e.IcicleErrorCode)
	} else {
		e := ecntt.ECNtt(pointsIcileProjective, core.KForward, &cfg, output)
		fmt.Println("IcicleErrorCode", e.IcicleErrorCode)
	}

	fmt.Println("ecntt time", time.Since(start), output.IsOnDevice())
	return output, nil
}

func ECNttPipeplinedFinal(pointsIcileProjective core.HostOrDeviceSlice, numSymbol int, batchSize int, isInverse bool) ([][]bn254.G1Affine, error) {
	cfg := setupEcntt(numSymbol, batchSize)

	totalNumSym := cfg.BatchSize * int32(numSymbol)

	output := make(core.HostSlice[icicle_bn254.Projective], int(totalNumSym))
	fmt.Println("totalNumSym", totalNumSym)

	e := ecntt.ECNtt(pointsIcileProjective, core.KForward, &cfg, output)
	fmt.Println("IcicleErrorCode", e.IcicleErrorCode)

	gpuFFTBatch := make([][]bn254.G1Affine, int(cfg.BatchSize))

	for j := 0; j < int(cfg.BatchSize); j++ {
		gpuFFTPoints := make([]bn254.G1Affine, numSymbol)
		for i := 0; i < int(numSymbol); i++ {
			gpuFFTPoints[i] = ProjectiveToGnarkAffine(output[i+j*numSymbol])

		}
		gpuFFTBatch[j] = gpuFFTPoints
		//for k := 0; k < len(gpuFFTPoints); k++ {
		//	fmt.Println("k", k, gpuFFTPoints[k].String())
		//}

	}

	return gpuFFTBatch, nil
}

func ECNtt(batchPoints []bn254.G1Affine, isInverse bool, batchSize int) ([]bn254.G1Affine, error) {
	numSymbol := len(batchPoints) / batchSize
	cfg := setupEcntt(numSymbol, batchSize)
	cfg.BatchSize = int32(batchSize)

	pointsIcileProjective := BatchConvertGnarkAffineToIcicleProjective(batchPoints)

	/*
		for i := 0; i < int(cfg.BatchSize); i++ {
			projs := BatchConvertGnarkAffineToIcicleProjective(batchPoints[i])

			pointsIcileProjective = append(pointsIcileProjective, projs...)

		}
	*/

	totalNumSym := len(batchPoints)

	copyStart := time.Now()
	pointsCopy := core.HostSliceFromElements[icicle_bn254.Projective](pointsIcileProjective)
	fmt.Println("copy takes", time.Since(copyStart))

	output := make(core.HostSlice[icicle_bn254.Projective], int(totalNumSym))
	fmt.Println("totalNumSym", totalNumSym)

	//var output core.DeviceSlice
	//output.Malloc(p.Size()*int(totalNumSym), p.Size())

	start := time.Now()

	if isInverse {
		e := ecntt.ECNtt(pointsCopy, core.KInverse, &cfg, output)
		fmt.Println("IcicleErrorCode", e.IcicleErrorCode)
	} else {
		e := ecntt.ECNtt(pointsCopy, core.KForward, &cfg, output)
		fmt.Println("IcicleErrorCode", e.IcicleErrorCode)
	}

	fmt.Println("ecntt time", time.Since(start))

	gpuFFTBatch := make([]bn254.G1Affine, len(batchPoints))

	for j := 0; j < totalNumSym; j++ {

		gpuFFTBatch[j] = ProjectiveToGnarkAffine(output[j])

	}

	return gpuFFTBatch, nil
}
