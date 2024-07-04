package gpu

import (
	"math"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
	"github.com/ingonyama-zk/icicle/v2/wrappers/golang/core"
	bn254_icicle "github.com/ingonyama-zk/icicle/v2/wrappers/golang/curves/bn254"
	"github.com/ingonyama-zk/icicle/v2/wrappers/golang/curves/bn254/ntt"
	bn254_icicle_ntt "github.com/ingonyama-zk/icicle/v2/wrappers/golang/curves/bn254/ntt"
)

func NTT(batchFr [][]fr.Element) ([][]fr.Element, error) {
	cfg := bn254_icicle_ntt.GetDefaultNttConfig()

	cfg.Ordering = core.KNN
	cfg.NttAlgorithm = core.Radix2

	numSymbol := len(batchFr[0])

	cfg.BatchSize = int32(len(batchFr))
	cfg.NttAlgorithm = core.Radix2

	exp := int32(math.Ceil(math.Log2(float64(numSymbol))))

	rouMont, _ := fft.Generator(uint64(1 << exp))
	rou := rouMont.Bits()
	rouIcicle := bn254_icicle.ScalarField{}

	limbs := core.ConvertUint64ArrToUint32Arr(rou[:])

	rouIcicle.FromLimbs(limbs)

	bn254_icicle_ntt.InitDomain(rouIcicle, cfg.Ctx, false)

	totalSize := int(numSymbol) * int(cfg.BatchSize)

	//flattenBatchFr := make([]fr.Element, 0, totalSize)
	flattenBatchFr := make([]fr.Element, 0)
	for i := 0; i < len(batchFr); i++ {
		flattenBatchFr = append(flattenBatchFr, batchFr[i]...)
	}
	//for i := 0; i < len(flattenBatchFr); i++ {
	//	fmt.Println("i", flattenBatchFr[i].String())
	//}

	flattenBatchSf := ConvertFrToScalarFieldsBytes(flattenBatchFr)

	scalarsCopy := core.HostSliceFromElements[bn254_icicle.ScalarField](flattenBatchSf)

	// run ntt
	output := make(core.HostSlice[bn254_icicle.ScalarField], totalSize)
	ntt.Ntt(scalarsCopy, core.KForward, &cfg, output)

	flattenBatchFrOutput := ConvertScalarFieldsToFrBytes(output)

	nttOutput := make([][]fr.Element, len(batchFr))
	for i := 0; i < len(batchFr); i++ {
		nttOutput[i] = flattenBatchFrOutput[i*numSymbol : (i+1)*numSymbol]
	}
	e := bn254_icicle_ntt.ReleaseDomain(cfg.Ctx)
	if e.IcicleErrorCode != core.IcicleErrorCode(0) {
		panic("ReleaseDomain failed")
	}

	return nttOutput, nil
}
