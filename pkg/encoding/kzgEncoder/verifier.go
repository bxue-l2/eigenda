package kzgEncoder

import (
	"bytes"
	"encoding/gob"
	"errors"
	"math"

	rs "github.com/Layr-Labs/eigenda/pkg/encoding/encoder"
	kzg "github.com/Layr-Labs/eigenda/pkg/kzg"
	bls "github.com/Layr-Labs/eigenda/pkg/kzg/bn254"
	wbls "github.com/Layr-Labs/eigenda/pkg/kzg/bn254"
)

type KzgVerifier struct {
	*KzgConfig
	Srs *kzg.SRS

	rs.EncodingParams

	Fs *kzg.FFTSettings
	Ks *kzg.KZGSettings
}

func (g *KzgEncoderGroup) GetKzgVerifier(params rs.EncodingParams) (*KzgVerifier, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if err := params.Validate(); err != nil {
		return nil, err
	}

	ver, ok := g.Verifiers[params]
	if ok {
		return ver, nil
	}

	ver, err := g.newKzgVerifier(params)
	if err == nil {
		g.Verifiers[params] = ver
	}

	return ver, err
}

func (g *KzgEncoderGroup) NewKzgVerifier(params rs.EncodingParams) (*KzgVerifier, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.newKzgVerifier(params)
}

func (g *KzgEncoderGroup) newKzgVerifier(params rs.EncodingParams) (*KzgVerifier, error) {

	if err := params.Validate(); err != nil {
		return nil, err
	}

	n := uint8(math.Log2(float64(params.NumEvaluations())))
	fs := kzg.NewFFTSettings(n)
	ks, err := kzg.NewKZGSettings(fs, g.Srs)

	if err != nil {
		return nil, err
	}

	return &KzgVerifier{
		KzgConfig:      g.KzgConfig,
		Srs:            g.Srs,
		EncodingParams: params,
		Fs:             fs,
		Ks:             ks,
	}, nil
}

// VerifyCommit verifies the low degree proof; since it doesn't depend on the encoding parameters
// we leave it as a method of the KzgEncoderGroup
func (v *KzgEncoderGroup) VerifyCommit(commit, lowDegreeProof *wbls.G1Point, degree uint64) error {

	if !VerifyLowDegreeProof(commit, lowDegreeProof, degree, v.SRSOrder, v.Srs.G2) {
		return errors.New("low degree proof fails")
	}
	return nil

}

func GenLenProofRandomness(commits []wbls.G1Point) (bls.Fr, error) {
	var buffer bytes.Buffer
	enc := gob.NewEncoder(&buffer)

	err := enc.Encode(commits)
	if err != nil {
		return bls.ZERO, err
	}

	var randomFr bls.Fr

	err = wbls.HashToSingleField(&randomFr, buffer.Bytes())
	if err != nil {
		return bls.ZERO, err
	}

	return randomFr, nil
}

func (v *KzgEncoderGroup) VerifyBatchedLengthProof(commits, lowDegreeProofs []wbls.G1Point, degrees []uint64) error {

	n := len(commits)

	r, err := GenLenProofRandomness(commits)
	if err != nil {
		return err
	}

	randomsFr := make([]bls.Fr, n)
	onesFr := make([]bls.Fr, n)

	wbls.CopyFr(&randomsFr[0], &r)

	var sumRandomsFr bls.Fr
	wbls.CopyFr(&sumRandomsFr, &wbls.ZERO)

	// power of r
	for j := 0; j < n-1; j++ {
		wbls.MulModFr(&randomsFr[j+1], &randomsFr[j], &r)
	}

	// sum of randomFr
	for j := 0; j < n; j++ {
		wbls.AddModFr(&sumRandomsFr, &sumRandomsFr, &randomsFr[j])
	}

	//for  batchedCommits
	for j := 0; j < n; j++ {
		wbls.CopyFr(&onesFr[j], &wbls.ONE)
	}

	batchedCommits := wbls.LinCombG1(commits, randomsFr)

	// claimed degree point, can potentially optimize by grouping nodes with same degree
	degreesPoint := make([]wbls.G2Point, n)
	for j := 0; j < n; j++ {
		claimedDegree := degrees[j]
		wbls.CopyG2(&degreesPoint[j], &v.Srs.G2[v.SRSOrder-1-claimedDegree])
	}

	batchedDegree := wbls.LinCombG2(degreesPoint, onesFr)

	// batched degree proof

	batchedProof := wbls.LinCombG1(lowDegreeProofs, onesFr)

	// batched G2
	var batchedG2 wbls.G2Point

	wbls.MulG2(&batchedG2, &bls.GenG2, &sumRandomsFr)

	if wbls.PairingsVerify(batchedCommits, batchedDegree, batchedProof, &batchedG2) {
		return nil
	} else {
		return errors.New("batched low degree proof fails")
	}

}

func (v *KzgVerifier) VerifyFrame(commit *wbls.G1Point, f *Frame, index uint64) error {

	j, err := rs.GetLeadingCosetIndex(
		uint64(index),
		v.NumChunks,
	)
	if err != nil {
		return err
	}

	if !f.Verify(v.Ks, commit, &v.Ks.ExpandedRootsOfUnity[j]) {
		return errors.New("multireveal proof fails")
	}

	return nil

}
