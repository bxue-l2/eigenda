package gpu

import (
	"fmt"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
	"github.com/ingonyama-zk/icicle/v2/wrappers/golang/core"
	bn254_icicle "github.com/ingonyama-zk/icicle/v2/wrappers/golang/curves/bn254"
	"github.com/ingonyama-zk/icicle/v2/wrappers/golang/curves/bn254/ntt"
	bn254_icicle_ntt "github.com/ingonyama-zk/icicle/v2/wrappers/golang/curves/bn254/ntt"
)

func (p *ParametrizedProver) NTTPipelined(batchFr [][]fr.Element, sfHostSlice core.HostOrDeviceSlice) error {

	//flattenBatchFr := make([]fr.Element, 0, totalSize)
	flattenBatchFr := make([]fr.Element, 0)
	for i := 0; i < len(batchFr); i++ {
		flattenBatchFr = append(flattenBatchFr, batchFr[i]...)
	}
	flattenBatchSf := ConvertFrToScalarFieldsBytes(flattenBatchFr)

	scalarsCopy := core.HostSliceFromElements[bn254_icicle.ScalarField](flattenBatchSf)

	ntt.Ntt(scalarsCopy, core.KForward, &p.cfg, sfHostSlice)
	/*
		e := bn254_icicle_ntt.ReleaseDomain(cfg.Ctx)
		if e.IcicleErrorCode != core.IcicleErrorCode(0) {
			panic("ReleaseDomain failed")
		}
	*/

	return nil
}

// batchSize is number of batches
func (p *ParametrizedProver) setupNTT(numSymbol int, batchSize int) core.NTTConfig[[bn254_icicle.SCALAR_LIMBS]uint32] {
	cfg := bn254_icicle_ntt.GetDefaultNttConfig()

	cfg.Ordering = core.KNN
	cfg.NttAlgorithm = core.Radix2

	cfg.BatchSize = int32(batchSize)
	cfg.NttAlgorithm = core.Radix2

	exp := 20 //int32(math.Ceil(math.Log2(float64(numSymbol))))

	rouMont, _ := fft.Generator(uint64(1 << exp))
	rou := rouMont.Bits()
	rouIcicle := bn254_icicle.ScalarField{}

	limbs := core.ConvertUint64ArrToUint32Arr(rou[:])

	rouIcicle.FromLimbs(limbs)

	bn254_icicle_ntt.InitDomain(rouIcicle, cfg.Ctx, false)

	return cfg
}

func (p *ParametrizedProver) NTT(batchFr [][]fr.Element) ([][]fr.Element, error) {
	numSymbol := len(batchFr[0])
	batchSize := len(batchFr)

	t0 := time.Now()

	totalSize := numSymbol * batchSize

	t1 := time.Now()
	//flattenBatchFr := make([]fr.Element, 0, totalSize)
	flattenBatchFr := make([]fr.Element, 0)
	for i := 0; i < len(batchFr); i++ {
		flattenBatchFr = append(flattenBatchFr, batchFr[i]...)
	}
	t2 := time.Now()
	flattenBatchSf := ConvertFrToScalarFieldsBytes(flattenBatchFr)

	scalarsCopy := core.HostSliceFromElements[bn254_icicle.ScalarField](flattenBatchSf)

	// run ntt
	output := make(core.HostSlice[bn254_icicle.ScalarField], totalSize)
	ntt.Ntt(scalarsCopy, core.KForward, &p.cfg, output)
	t3 := time.Now()
	flattenBatchFrOutput := ConvertScalarFieldsToFrBytes(output)

	nttOutput := make([][]fr.Element, len(batchFr))
	for i := 0; i < len(batchFr); i++ {
		nttOutput[i] = flattenBatchFrOutput[i*numSymbol : (i+1)*numSymbol]
	}
	t4 := time.Now()

	t5 := time.Now()
	fmt.Println(t1.Sub(t0), t2.Sub(t1), t3.Sub(t2), t4.Sub(t3), t5.Sub(t4))

	return nttOutput, nil
}
