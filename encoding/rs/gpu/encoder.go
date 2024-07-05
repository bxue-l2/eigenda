package gpu

import (
	"math"
	"runtime"

	"github.com/Layr-Labs/eigenda/encoding"
	"github.com/Layr-Labs/eigenda/encoding/fft"
	gnark_fft "github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
	"github.com/ingonyama-zk/icicle/v2/wrappers/golang/core"
	icicle_bn254 "github.com/ingonyama-zk/icicle/v2/wrappers/golang/curves/bn254"
	"github.com/ingonyama-zk/icicle/v2/wrappers/golang/curves/bn254/ntt"
)

type Encoder struct {
	encoding.EncodingParams

	Fs *fft.FFTSettings

	verbose bool

	NumRSWorker int

	nttCfg core.NTTConfig[[icicle_bn254.SCALAR_LIMBS]uint32]
}

// The function creates a high level struct that determines the encoding the a data of a
// specific length under (num systematic node, num parity node) setup. A systematic node
// stores a systematic data chunk that contains part of the original data. A parity node
// stores a parity data chunk which is an encoding of the original data. A receiver that
// collects all systematic chunks can simply stitch data together to reconstruct the
// original data. When some systematic chunks are missing but identical parity chunk are
// available, the receive can go through a Reed Solomon decoding to reconstruct the
// original data.
func NewEncoder(params encoding.EncodingParams, verbose bool) (*Encoder, error) {

	err := params.Validate()
	if err != nil {
		return nil, err
	}

	n := uint8(math.Log2(float64(params.NumEvaluations())))
	fs := fft.NewFFTSettings(n)

	cfg := ntt.GetDefaultNttConfig()
	exp := 28 // max blob size after encoding 2^exp
	rouMont, _ := gnark_fft.Generator(uint64(1 << exp))
	rou := rouMont.Bits()
	rouIcicle := icicle_bn254.ScalarField{}
	limbs := core.ConvertUint64ArrToUint32Arr(rou[:])

	rouIcicle.FromLimbs(limbs)
	ntt.InitDomain(rouIcicle, cfg.Ctx, false)

	return &Encoder{
		EncodingParams: params,
		Fs:             fs,
		verbose:        verbose,
		NumRSWorker:    runtime.GOMAXPROCS(0),
		nttCfg:         cfg,
	}, nil
}
