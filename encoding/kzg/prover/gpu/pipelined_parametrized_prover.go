package gpu

import (
	"fmt"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/ingonyama-zk/icicle/v2/wrappers/golang/core"
	cr "github.com/ingonyama-zk/icicle/v2/wrappers/golang/cuda_runtime"
	bn254_icicle "github.com/ingonyama-zk/icicle/v2/wrappers/golang/curves/bn254"
	"github.com/ingonyama-zk/icicle/v2/wrappers/golang/curves/bn254/vecOps"
)

func (p *ParametrizedProver) ProveAllCosetThreadsPipeline(polyFr []fr.Element, numChunks, chunkLen, numWorker uint64) ([]bn254.G1Affine, error) {
	begin := time.Now()
	// Robert: Standardizing this to use the same math used in precomputeSRS
	dimE := numChunks
	l := chunkLen

	jobChan := make(chan uint64, numWorker)
	results := make(chan WorkerResult, numWorker)

	// create storage for intermediate fft outputs
	coeffStore := make([][]fr.Element, l) //dimE*2
	for i := range coeffStore {
		coeffStore[i] = make([]fr.Element, dimE*2)
	}

	for w := uint64(0); w < numWorker; w++ {
		go p.proofWorkerGPU(polyFr, jobChan, l, dimE, coeffStore, results)
	}

	for j := uint64(0); j < l; j++ {
		jobChan <- j
	}
	close(jobChan)

	// return last error
	var err error
	for w := uint64(0); w < numWorker; w++ {
		wr := <-results
		if wr.err != nil {
			err = wr.err
		}
	}

	if err != nil {
		return nil, fmt.Errorf("proof worker error: %v", err)
	}

	fmt.Println("NTT")

	numSymbol := len(coeffStore[0])
	batchSize := len(coeffStore)

	totalSize := len(coeffStore) * len(coeffStore[0])
	nttOutput := make(core.HostSlice[bn254_icicle.ScalarField], totalSize)

	e := p.NTTPipelined(coeffStore, nttOutput)
	if e != nil {
		return nil, e
	}

	// transpose it
	fmt.Println("ECNTT inverse", "batchSize", batchSize, "numSymbol", numSymbol)
	ctx, _ := cr.GetDefaultDeviceContext()
	transposedNTTOutput := make(core.HostSlice[bn254_icicle.ScalarField], totalSize)
	vecOps.TransposeMatrix(nttOutput, transposedNTTOutput, int(l), int(dimE*2), ctx, false, false)

	/*
		fmt.Println("TransposeFFT")
		transposeFr := ConvertScalarFieldsToFrBytes(transposedNTTOutput)
		for i := 0; i < len(transposedNTTOutput); i++ {
			fmt.Printf("%v ", transposeFr[i].String())
		}
		fmt.Println()
	*/

	t0 := time.Now()
	fmt.Println("MsmBatch")
	sumVecDevice, err := MsmBatchPipelined(transposedNTTOutput, p.FFTPointsT)
	if err != nil {
		return nil, err
	}

	t1 := time.Now()
	numSymbol = len(p.FFTPointsT)
	batchSize = 1 //single blob
	fmt.Println("ECNTT inverse", "batchSize", batchSize, "numSymbol", numSymbol)
	sumVecInvBatch, err := ECNttPipeplined(sumVecDevice, numSymbol, batchSize, true)
	if err != nil {
		return nil, err
	}

	t2 := time.Now()

	// outputs is out of order - buttefly
	fmt.Println("ECNTT last")
	numSymbol = len(p.FFTPointsT) / 2
	batchSize = 2 //single blob, but pretend there are two, since we cannot truncate

	proofsBatch, err := ECNttPipeplinedFinal(sumVecInvBatch, numSymbol, batchSize, false)
	if err != nil {
		return nil, fmt.Errorf("second ECNtt error: %w", err)
	}
	proofs := proofsBatch[0]

	t3 := time.Now()

	fmt.Printf("total %v mult-th %v, msm %v,fft1 %v, fft2 %v,\n", t3.Sub(begin), t0.Sub(begin), t1.Sub(t0), t2.Sub(t1), t3.Sub(t2))

	return proofs, nil
}
