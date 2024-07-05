package gpu

import (
	"fmt"
	"log"
	"math"
	"time"

	"github.com/Layr-Labs/eigenda/encoding"
	"github.com/ingonyama-zk/icicle/v2/wrappers/golang/core"
	bn254_icicle "github.com/ingonyama-zk/icicle/v2/wrappers/golang/curves/bn254"

	"github.com/Layr-Labs/eigenda/encoding/fft"
	"github.com/Layr-Labs/eigenda/encoding/kzg"
	"github.com/Layr-Labs/eigenda/encoding/rs"
	cpu_rs "github.com/Layr-Labs/eigenda/encoding/rs/cpu"
	"github.com/Layr-Labs/eigenda/encoding/utils/toeplitz"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

type ParametrizedProver struct {
	*cpu_rs.Encoder

	*kzg.KzgConfig
	Srs        *kzg.SRS
	G2Trailing []bn254.G2Affine

	Fs               *fft.FFTSettings
	Ks               *kzg.KZGSettings
	SFs              *fft.FFTSettings   // fft used for submatrix product helper
	FFTPointsT       [][]bn254.G1Affine // transpose of FFTPoints
	PrecomputedSRSG1 core.DeviceSlice
	MsmCfg           core.MSMConfig

	cfg core.NTTConfig[[bn254_icicle.SCALAR_LIMBS]uint32]
}

type WorkerResult struct {
	points []bn254.G1Affine
	err    error
}

// just a wrapper to take bytes not Fr Element
func (g *ParametrizedProver) EncodeBytes(inputBytes []byte) (*bn254.G1Affine, *bn254.G2Affine, *bn254.G2Affine, []encoding.Frame, []uint32, error) {
	inputFr, err := rs.ToFrArray(inputBytes)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("cannot convert bytes to field elements, %w", err)
	}
	return g.Encode(inputFr)
}

func (g *ParametrizedProver) Encode(inputFr []fr.Element) (*bn254.G1Affine, *bn254.G2Affine, *bn254.G2Affine, []encoding.Frame, []uint32, error) {

	startTime := time.Now()
	poly, frames, indices, err := g.Encoder.Encode(inputFr)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	if len(poly.Coeffs) > int(g.KzgConfig.SRSNumberToLoad) {
		return nil, nil, nil, nil, nil, fmt.Errorf("poly Coeff length %v is greater than Loaded SRS points %v", len(poly.Coeffs), int(g.KzgConfig.SRSNumberToLoad))
	}

	// compute commit for the full poly
	commit, err := g.Commit(poly.Coeffs)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	config := ecc.MultiExpConfig{}

	var lengthCommitment bn254.G2Affine
	_, err = lengthCommitment.MultiExp(g.Srs.G2[:len(poly.Coeffs)], poly.Coeffs, config)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	intermediate := time.Now()

	chunkLength := uint64(len(inputFr))

	if g.Verbose {
		log.Printf("    Commiting takes  %v\n", time.Since(intermediate))
		intermediate = time.Now()

		log.Printf("shift %v\n", g.SRSOrder-chunkLength)
		log.Printf("order %v\n", len(g.Srs.G2))
		log.Println("low degree verification info")
	}

	shiftedSecret := g.G2Trailing[g.KzgConfig.SRSNumberToLoad-chunkLength:]

	//The proof of low degree is commitment of the polynomial shifted to the largest srs degree
	var lengthProof bn254.G2Affine
	_, err = lengthProof.MultiExp(shiftedSecret, poly.Coeffs, config)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	if g.Verbose {
		log.Printf("    Generating Length Proof takes  %v\n", time.Since(intermediate))
		intermediate = time.Now()
	}

	// compute proofs
	paddedCoeffs := make([]fr.Element, g.NumEvaluations())
	copy(paddedCoeffs, poly.Coeffs)

	inputFrBatch := make([][]fr.Element, 10)
	for i := 0; i < len(inputFrBatch); i++ {
		inputFrBatch[i] = paddedCoeffs
	}

	proofsBatched, err := g.ProveBatchedCoset(inputFrBatch, g.NumChunks, g.ChunkLength, g.NumWorker)
	proofs := proofsBatched[0]
	//proofs, err := g.ProveAllCosetThreads(paddedCoeffs, g.NumChunks, g.ChunkLength, g.NumWorker)
	//proofs, err := g.ProveAllCosetThreadsPipeline(paddedCoeffs, g.NumChunks, g.ChunkLength, g.NumWorker)

	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("could not generate proofs: %v", err)
	}

	if g.Verbose {
		log.Printf("    Proving takes    %v\n", time.Since(intermediate))
	}

	kzgFrames := make([]encoding.Frame, len(frames))
	for i, index := range indices {
		kzgFrames[i] = encoding.Frame{
			Proof:  proofs[index],
			Coeffs: frames[i].Coeffs,
		}
	}

	if g.Verbose {
		log.Printf("Total encoding took      %v\n", time.Since(startTime))
	}
	return &commit, &lengthCommitment, &lengthProof, kzgFrames, indices, nil
}

func (g *ParametrizedProver) Commit(polyFr []fr.Element) (bn254.G1Affine, error) {
	commit, err := g.Ks.CommitToPoly(polyFr)
	return *commit, err
}

// assume numChunk, numLen are identical
func (p *ParametrizedProver) ProveBatchedCoset(polyFrList [][]fr.Element, numChunks, chunkLen, numWorker uint64) ([][]bn254.G1Affine, error) {
	start := time.Now()
	numPoly := len(polyFrList)
	flatPolyFr := make([]fr.Element, 0, numPoly*len(polyFrList[0]))
	for i := 0; i < numPoly; i++ {
		flatPolyFr = append(flatPolyFr, polyFrList[i]...)
	}
	/*
		fmt.Println("flatPolyFr")
		for i := 0; i < len(flatPolyFr); i++ {
			fmt.Printf("%v ", flatPolyFr[i].String())
		}
		fmt.Println()
	*/
	flatProofsBatch, err := p.ProveAllCosetThreads(flatPolyFr, numChunks, chunkLen, numWorker)
	if err != nil {
		return nil, err
	}

	proofsBatch := make([][]bn254.G1Affine, numPoly)
	for i := uint64(0); i < uint64(numPoly); i++ {
		proofsBatch[i] = flatProofsBatch[i*numChunks : (i+1)*numChunks]
		//for j := 0; j < len(proofsBatch[i]); j++ {
		//	fmt.Printf("%v ", proofsBatch[i][j].String())
		//}
		//fmt.Println()
	}
	fmt.Println("prove batch takes", time.Since(start))
	return proofsBatch, nil
}

func (p *ParametrizedProver) ProveAllCosetThreads(polyFr []fr.Element, numChunks, chunkLen, numWorker uint64) ([]bn254.G1Affine, error) {

	// Robert: Standardizing this to use the same math used in precomputeSRS
	dimE := numChunks
	l := chunkLen
	numPoly := uint64(len(polyFr)) / dimE / chunkLen
	fmt.Println("numPoly", numPoly)

	p.cfg = p.setupNTT(int(dimE*2), int(l*numPoly))

	begin := time.Now()
	jobChan := make(chan uint64, numWorker)
	results := make(chan WorkerResult, numWorker)

	// create storage for intermediate fft outputs
	coeffStore := make([][]fr.Element, l*numPoly)
	for i := range coeffStore {
		coeffStore[i] = make([]fr.Element, dimE*2)
	}

	fmt.Println("len(polyFr)", len(polyFr))

	for w := uint64(0); w < numWorker; w++ {
		go p.proofWorkerGPU(polyFr, jobChan, l, dimE, coeffStore, results)
	}

	for j := uint64(0); j < l*numPoly; j++ {
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
	t_prepare := time.Now()

	if err != nil {
		return nil, fmt.Errorf("proof worker error: %v", err)
	}

	/*
		fmt.Println("coeffStore")
		for i := 0; i < len(coeffStore); i++ {
			a := coeffStore[i]
			for j := 0; j < len(a); j++ {
				fmt.Printf("%v ", a[j].String())
			}
			fmt.Println()
		}
	*/

	fmt.Println("NTT")
	coeffStoreFFT, e := p.NTT(coeffStore)
	if e != nil {
		return nil, e
	}

	// transpose it

	coeffStoreFFTT := make([][]fr.Element, dimE*2*numPoly)
	for i := range coeffStoreFFTT {
		coeffStoreFFTT[i] = make([]fr.Element, l)
	}

	t_ntt := time.Now()

	for k := uint64(0); k < numPoly; k++ {
		step := int(k * dimE * 2)
		for i := 0; i < int(l); i++ {
			vec := coeffStoreFFT[i+int(k*l)]
			for j := 0; j < int(dimE*2); j++ {
				coeffStoreFFTT[j+step][i] = vec[j]
			}
		}
	}

	/*
		fmt.Println("Transposed FFT")
		for i := 0; i < len(coeffStore); i++ {
			vec := coeffStoreFFT[i]
			for j := 0; j < len(vec); j++ {
				fmt.Printf("%v ", vec[j].String())
			}
			fmt.Println()
		}
	*/

	t0 := time.Now()
	fmt.Println("MsmBatch")
	sumVec, err := MsmBatch(coeffStoreFFTT, p.FFTPointsT)
	if err != nil {
		return nil, err
	}

	t1 := time.Now()

	fmt.Println("ECNTT inverse")
	sumVecInv, err := ECNtt(sumVec, true, int(numPoly))
	if err != nil {
		return nil, err
	}

	t2 := time.Now()

	// remove half points per poly
	batchInv := make([]bn254.G1Affine, len(sumVecInv)/2)
	// outputs is out of order - buttefly
	k := 0
	for i := 0; i < int(numPoly); i++ {
		for j := 0; j < int(dimE); j++ {
			batchInv[k] = sumVecInv[i*int(dimE)*2+j]
			k += 1
		}
	}
	fmt.Println("ECNTT last")
	flatProofsBatch, err := ECNtt(batchInv, false, int(numPoly))
	if err != nil {
		return nil, fmt.Errorf("second ECNtt error: %w", err)
	}

	t3 := time.Now()

	fmt.Printf("prepare %v, ntt %v,\n", t_prepare.Sub(begin), t_ntt.Sub(t_prepare))
	fmt.Printf("total %v mult-th %v, msm %v,fft1 %v, fft2 %v,\n", t3.Sub(begin), t0.Sub(begin), t1.Sub(t0), t2.Sub(t1), t3.Sub(t2))

	return flatProofsBatch, nil
}

func (p *ParametrizedProver) proofWorker(
	polyFr []fr.Element,
	jobChan <-chan uint64,
	l uint64,
	dimE uint64,
	coeffStore [][]fr.Element,
	results chan<- WorkerResult,
) {

	for j := range jobChan {
		coeffs, err := p.GetSlicesCoeff(polyFr, dimE, j, l)

		if err != nil {
			results <- WorkerResult{
				points: nil,
				err:    err,
			}
		} else {
			for i := 0; i < len(coeffs); i++ {
				coeffStore[j][i] = coeffs[i]
			}
		}
	}

	results <- WorkerResult{
		err: nil,
	}
}

func (p *ParametrizedProver) proofWorkerGPU(
	polyFr []fr.Element,
	jobChan <-chan uint64,
	l uint64,
	dimE uint64,
	coeffStore [][]fr.Element,
	results chan<- WorkerResult,
) {

	for j := range jobChan {
		coeffs, err := p.GetSlicesCoeffBeforeFFT(polyFr, dimE, j, l)

		if err != nil {
			results <- WorkerResult{
				points: nil,
				err:    err,
			}
		} else {
			for i := 0; i < len(coeffs); i++ {
				coeffStore[j][i] = coeffs[i]
			}
		}
	}

	results <- WorkerResult{
		err: nil,
	}
}

func (p *ParametrizedProver) GetSlicesCoeff(polyFr []fr.Element, dimE, j, l uint64) ([]fr.Element, error) {
	// there is a constant term
	m := uint64(len(polyFr)) - 1

	dim := (m - j) / l

	toeV := make([]fr.Element, 2*dimE-1)
	for i := uint64(0); i < dim; i++ {

		toeV[i].Set(&polyFr[m-(j+i*l)])
	}

	// use precompute table
	tm, err := toeplitz.NewToeplitz(toeV, p.SFs)
	if err != nil {
		return nil, err
	}
	return tm.GetFFTCoeff()
}

// output is in the form see primeField toeplitz
//
// phi ^ (coset size ) = 1
//
// implicitly pad slices to power of 2
func (p *ParametrizedProver) GetSlicesCoeffBeforeFFT(polyFr []fr.Element, dimE, j, l uint64) ([]fr.Element, error) {
	// there is a constant term
	m := uint64(dimE*l) - 1
	dim := (m - j%l) / l
	k := j % l
	q := j / l
	//fmt.Println("polyFr", len(polyFr), "dim", dim, "j", j, "l", l)
	//fmt.Println("q", q, "j", j, "l", l, "dimE", dimE)
	toeV := make([]fr.Element, 2*dimE-1)
	for i := uint64(0); i < dim; i++ {
		//	fmt.Println(i, m+q*l-(k+i*l))

		toeV[i].Set(&polyFr[m+dimE*l*q-(k+i*l)])

	}

	// use precompute table
	tm, err := toeplitz.NewToeplitz(toeV, p.SFs)
	if err != nil {
		return nil, err
	}
	return tm.GetCoeff()
}

/*
returns the power of 2 which is immediately bigger than the input
*/
func CeilIntPowerOf2Num(d uint64) uint64 {
	nextPower := math.Ceil(math.Log2(float64(d)))
	return uint64(math.Pow(2.0, nextPower))
}
