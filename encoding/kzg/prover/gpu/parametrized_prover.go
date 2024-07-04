package gpu

import (
	"fmt"
	"log"
	"math"
	"time"

	"github.com/Layr-Labs/eigenda/encoding"

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

	Fs         *fft.FFTSettings
	Ks         *kzg.KZGSettings
	SFs        *fft.FFTSettings   // fft used for submatrix product helper
	FFTPointsT [][]bn254.G1Affine // transpose of FFTPoints

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

	proofs, err := g.ProveAllCosetThreads(paddedCoeffs, g.NumChunks, g.ChunkLength, g.NumWorker)
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

func (p *ParametrizedProver) ProveAllCosetThreads(polyFr []fr.Element, numChunks, chunkLen, numWorker uint64) ([]bn254.G1Affine, error) {
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
	coeffStoreFFT, e := NTT(coeffStore)
	if e != nil {
		return nil, e
	}

	// transpose it
	coeffStoreFFTT := make([][]fr.Element, dimE*2)
	for i := range coeffStoreFFTT {
		coeffStoreFFTT[i] = make([]fr.Element, l)
	}

	for i := 0; i < len(coeffStore); i++ {
		vec := coeffStoreFFT[i]
		for j := 0; j < len(vec); j++ {
			coeffStoreFFTT[j][i] = vec[j]
		}
	}

	t0 := time.Now()
	fmt.Println("MsmBatch")
	sumVec, err := MsmBatch(coeffStoreFFTT, p.FFTPointsT)
	if err != nil {
		return nil, err
	}

	t1 := time.Now()

	batch := make([][]bn254.G1Affine, 1)
	batch[0] = sumVec
	fmt.Println("ECNTT inverse")
	sumVecInvBatch, err := ECNtt(batch, true)
	if err != nil {
		return nil, err
	}
	sumVecInv := sumVecInvBatch[0]

	t2 := time.Now()

	batchInv := make([][]bn254.G1Affine, 1)
	// outputs is out of order - buttefly
	batchInv[0] = sumVecInv[:dimE]
	fmt.Println("ECNTT last")
	proofss, err := ECNtt(batchInv, false)
	if err != nil {
		return nil, fmt.Errorf("second ECNtt error: %w", err)
	}
	proofs := proofss[0]

	t3 := time.Now()

	fmt.Printf("total %v mult-th %v, msm %v,fft1 %v, fft2 %v,\n", t3.Sub(begin), t0.Sub(begin), t1.Sub(t0), t2.Sub(t1), t3.Sub(t2))

	return proofs, nil
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
	return tm.GetCoeff()
}

/*
returns the power of 2 which is immediately bigger than the input
*/
func CeilIntPowerOf2Num(d uint64) uint64 {
	nextPower := math.Ceil(math.Log2(float64(d)))
	return uint64(math.Pow(2.0, nextPower))
}

/*
	fmt.Println("coeffStoreFFT")
	for i := 0; i < len(coeffStoreFFT); i++ {
		a := coeffStoreFFT[i]
		for j := 0; j < len(a); j++ {
			fmt.Printf("%v ", a[j].String())
		}
		fmt.Println()
	}
*/
