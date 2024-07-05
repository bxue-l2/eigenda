package gpu

import (
	"fmt"
	"log"
	"math"
	"time"

	"github.com/Layr-Labs/eigenda/encoding"
	"github.com/Layr-Labs/eigenda/encoding/rs"
	rb "github.com/Layr-Labs/eigenda/encoding/utils/reverseBits"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"

	"github.com/ingonyama-zk/icicle/v2/wrappers/golang/core"
	"github.com/ingonyama-zk/icicle/v2/wrappers/golang/curves/bn254"
	icicle_bn254 "github.com/ingonyama-zk/icicle/v2/wrappers/golang/curves/bn254"
	"github.com/ingonyama-zk/icicle/v2/wrappers/golang/curves/bn254/ntt"
)

type GlobalPoly struct {
	Coeffs []fr.Element
	Values []fr.Element
}

// just a wrapper to take bytes not Fr Element
func (g *Encoder) EncodeBytes(inputBytes []byte) (*GlobalPoly, []rs.Frame, []uint32, error) {
	inputFr, err := rs.ToFrArray(inputBytes)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("cannot convert bytes to field elements, %w", err)
	}
	return g.Encode(inputFr)
}

// Encode function takes input in unit of Fr Element, creates a kzg commit and a list of frames
// which contains a list of multireveal interpolating polynomial coefficients, a G1 proof and a
// low degree proof corresponding to the interpolating polynomial. Each frame is an independent
// group of data verifiable to the kzg commitment. The encoding functions ensures that in each
// frame, the multireveal interpolating coefficients are identical to the part of input bytes
// in the form of field element. The extra returned integer list corresponds to which leading
// coset root of unity, the frame is proving against, which can be deduced from a frame's index
func (g *Encoder) Encode(inputFr []fr.Element) (*GlobalPoly, []rs.Frame, []uint32, error) {
	start := time.Now()
	intermediate := time.Now()

	polyCoeffs := inputFr

	// extend data based on Sys, Par ratio. The returned fullCoeffsPoly is padded with 0 to ease proof
	polyEvals, _, err := g.ExtendPolyEval(polyCoeffs)
	if err != nil {
		return nil, nil, nil, err
	}

	poly := &GlobalPoly{
		Values: polyEvals,
		Coeffs: polyCoeffs,
	}

	if g.verbose {
		log.Printf("    Extending evaluation takes  %v\n", time.Since(intermediate))
	}

	// create frames to group relevant info
	frames, indices, err := g.MakeFrames(polyEvals)
	if err != nil {
		return nil, nil, nil, err
	}

	log.Printf("  SUMMARY: RSEncode %v byte among %v numChunks with chunkLength %v takes %v\n",
		len(inputFr)*encoding.BYTES_PER_SYMBOL, g.NumChunks, g.ChunkLength, time.Since(start))

	return poly, frames, indices, nil
}

// This Function takes extended evaluation data and bundles relevant information into Frame.
// Every frame is verifiable to the commitment.
func (g *Encoder) MakeFrames(
	polyEvals []fr.Element,
) ([]rs.Frame, []uint32, error) {
	// reverse dataFr making easier to sample points
	err := rb.ReverseBitOrderFr(polyEvals)
	if err != nil {
		return nil, nil, err
	}

	indices := make([]uint32, 0)
	frames := make([]rs.Frame, g.NumChunks)

	g.interpolyWorker(
		polyEvals,
		frames,
	)

	for i := uint64(0); i < g.NumChunks; i++ {
		j := rb.ReverseBitsLimited(uint32(g.NumChunks), uint32(i))
		indices = append(indices, j)
	}

	return frames, indices, nil
}

// Encoding Reed Solomon using FFT
func (g *Encoder) ExtendPolyEval(coeffs []fr.Element) ([]fr.Element, []fr.Element, error) {

	if len(coeffs) > int(g.NumEvaluations()) {
		return nil, nil, fmt.Errorf("the provided encoding parameters are not sufficient for the size of the data input")
	}

	pdCoeffs := make([]fr.Element, g.NumEvaluations())
	for i := 0; i < len(coeffs); i++ {
		pdCoeffs[i].Set(&coeffs[i])
	}
	// Padding to GPU
	for i := len(coeffs); i < len(pdCoeffs); i++ {
		pdCoeffs[i].SetZero()
	}

	cfg := ntt.GetDefaultNttConfig()

	exp := int(math.Ceil(math.Log2(float64(len(pdCoeffs)))))

	rouMont, _ := fft.Generator(uint64(1 << exp))
	rou := rouMont.Bits()
	rouIcicle := icicle_bn254.ScalarField{}
	limbs := core.ConvertUint64ArrToUint32Arr(rou[:])

	rouIcicle.FromLimbs(limbs)
	ntt.InitDomain(rouIcicle, cfg.Ctx, false)

	scalars := ConvertFromFrToHostDeviceSlice(pdCoeffs)

	outputDevice := make(core.HostSlice[icicle_bn254.ScalarField], len(pdCoeffs))

	ntt.Ntt(scalars, core.KForward, &cfg, outputDevice)

	outputAsFr := ConvertScalarFieldsToFrBytes(outputDevice)

	return outputAsFr, pdCoeffs, nil
}

func (g *Encoder) interpolyWorker(
	polyEvals []fr.Element,
	frames []rs.Frame,
) {

	for i := uint64(0); i < uint64(len(frames)); i++ {
		ys := polyEvals[g.ChunkLength*i : g.ChunkLength*(i+1)]
		err := rb.ReverseBitOrderFr(ys)
		if err != nil {
			continue
		}
	}

	batchSize := len(frames)

	cfg := ntt.GetDefaultNttConfig()

	cfg.BatchSize = int32(batchSize)

	exp := int(math.Ceil(math.Log2(float64(g.NumEvaluations()))))
	//fmt.Println("exp is", exp)
	rouMont, _ := fft.Generator(uint64(1 << exp))
	rou := rouMont.Bits()
	rouIcicle := icicle_bn254.ScalarField{}

	limbs := core.ConvertUint64ArrToUint32Arr(rou[:])

	rouIcicle.FromLimbs(limbs)

	ntt.InitDomain(rouIcicle, cfg.Ctx, false)

	scalars := ConvertFromFrToHostDeviceSlice(polyEvals)

	outputDevice := make(core.HostSlice[bn254.ScalarField], len(polyEvals))

	ntt.Ntt(scalars, core.KInverse, &cfg, outputDevice)

	outputAsFr := ConvertScalarFieldsToFrBytes(outputDevice)

	mod := int32(len(g.Fs.ExpandedRootsOfUnity) - 1)

	for i := uint64(0); i < uint64(len(frames)); i++ {
		chunk := outputAsFr[i*g.ChunkLength : (i+1)*g.ChunkLength]
		k := rb.ReverseBitsLimited(uint32(g.NumChunks), uint32(i))

		for z := 0; z < len(chunk); z++ {
			// We can lookup the inverse power by counting RootOfUnity backward
			j := (-int32(k)*int32(z))%mod + mod
			frames[i].Coeffs[z].Mul(&chunk[z], &g.Fs.ExpandedRootsOfUnity[j])
		}
	}
}
