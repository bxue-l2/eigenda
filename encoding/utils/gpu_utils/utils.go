//go:build gpu
// +build gpu

package gpu_utils

import (
	"math"
	"sync"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/ingonyama-zk/icicle/v2/wrappers/golang/core"
	bn254_icicle "github.com/ingonyama-zk/icicle/v2/wrappers/golang/curves/bn254"
	bn254_icicle_g2 "github.com/ingonyama-zk/icicle/v2/wrappers/golang/curves/bn254/g2"
)

func ConvertFrToScalarFieldsBytes(data []fr.Element) []bn254_icicle.ScalarField {
	scalars := make([]bn254_icicle.ScalarField, len(data))

	for i := 0; i < len(data); i++ {
		src := data[i] // 4 uint64
		var littleEndian [32]byte

		fr.LittleEndian.PutElement(&littleEndian, src)
		scalars[i].FromBytesLittleEndian(littleEndian[:])
	}
	return scalars
}

func ConvertScalarFieldsToFrBytes(scalars []bn254_icicle.ScalarField) []fr.Element {
	frElements := make([]fr.Element, len(scalars))

	for i := 0; i < len(frElements); i++ {
		v := scalars[i]
		slice64, _ := fr.LittleEndian.Element((*[fr.Bytes]byte)(v.ToBytesLittleEndian()))
		frElements[i] = slice64
	}
	return frElements
}

// Very important, if want target to be projective, do not use this function. Use the one below
func BatchConvertGnarkAffineToIcicleAffine(gAffineList []bn254.G1Affine) []bn254_icicle.Affine {
	icicleAffineList := make([]bn254_icicle.Affine, len(gAffineList))
	for i := 0; i < len(gAffineList); i++ {
		GnarkAffineToIcicleAffine(&gAffineList[i], &icicleAffineList[i])
	}
	return icicleAffineList
}

// Very important, if want target to be projective, do not use this function. Use the one below
func BatchConvertGnarkG2AffineToIcicleAffine(gAffineList []bn254.G2Affine) []bn254_icicle_g2.G2Affine {
	icicleAffineList := make([]bn254_icicle_g2.G2Affine, len(gAffineList))
	for i := 0; i < len(gAffineList); i++ {
		G2GnarkAffineToIcicleAffine(&gAffineList[i], &icicleAffineList[i])
	}
	return icicleAffineList
}

func GnarkAffineToIcicleAffine(g1 *bn254.G1Affine, iciAffine *bn254_icicle.Affine) {
	var littleEndBytesX, littleEndBytesY [32]byte
	fp.LittleEndian.PutElement(&littleEndBytesX, g1.X)
	fp.LittleEndian.PutElement(&littleEndBytesY, g1.Y)

	iciAffine.X.FromBytesLittleEndian(littleEndBytesX[:])
	iciAffine.Y.FromBytesLittleEndian(littleEndBytesY[:])
}

func G2GnarkAffineToIcicleAffine(g2 *bn254.G2Affine, iciAffine *bn254_icicle_g2.G2Affine) {
	var littleEndBytesXA0, littleEndBytesXA1 [32]byte
	fp.LittleEndian.PutElement(&littleEndBytesXA0, g2.X.A0)
	fp.LittleEndian.PutElement(&littleEndBytesXA1, g2.X.A1)

	var littleEndBytesYA0, littleEndBytesYA1 [32]byte

	fp.LittleEndian.PutElement(&littleEndBytesYA0, g2.Y.A0)
	fp.LittleEndian.PutElement(&littleEndBytesYA1, g2.Y.A1)

	iciAffine.X.FromBytesLittleEndian(append(littleEndBytesXA0[:], littleEndBytesXA1[:]...))
	iciAffine.Y.FromBytesLittleEndian(append(littleEndBytesYA0[:], littleEndBytesYA1[:]...))
}

func BatchConvertGnarkAffineToIcicleProjective(gAffineList []bn254.G1Affine) []bn254_icicle.Projective {
	icicleProjectiveList := make([]bn254_icicle.Projective, len(gAffineList))
	var icicleAffine bn254_icicle.Affine

	for i := 0; i < len(gAffineList); i++ {
		GnarkAffineToIcicleAffine(&gAffineList[i], &icicleAffine)
		icicleProjectiveList[i] = icicleAffine.ToProjective()
	}

	return icicleProjectiveList
}

func IcicleProjectiveToGnarkAffine(p bn254_icicle.Projective) bn254.G1Affine {
	px, _ := fp.LittleEndian.Element((*[fp.Bytes]byte)((&p.X).ToBytesLittleEndian()))
	py, _ := fp.LittleEndian.Element((*[fp.Bytes]byte)((&p.Y).ToBytesLittleEndian()))
	pz, _ := fp.LittleEndian.Element((*[fp.Bytes]byte)((&p.Z).ToBytesLittleEndian()))

	zInv := new(fp.Element)
	x := new(fp.Element)
	y := new(fp.Element)

	zInv.Inverse(&pz)

	x.Mul(&px, zInv)
	y.Mul(&py, zInv)

	return bn254.G1Affine{X: *x, Y: *y}
}

func G2IcicleProjectiveToG2GnarkAffine(p bn254_icicle_g2.G2Projective) bn254.G2Affine {
	pxBytes := p.X.ToBytesLittleEndian()
	pxA0, _ := fp.LittleEndian.Element((*[fp.Bytes]byte)(pxBytes[:fp.Bytes]))
	pxA1, _ := fp.LittleEndian.Element((*[fp.Bytes]byte)(pxBytes[fp.Bytes:]))
	x := bn254.E2{
		A0: pxA0,
		A1: pxA1,
	}

	pyBytes := p.Y.ToBytesLittleEndian()
	pyA0, _ := fp.LittleEndian.Element((*[fp.Bytes]byte)(pyBytes[:fp.Bytes]))
	pyA1, _ := fp.LittleEndian.Element((*[fp.Bytes]byte)(pyBytes[fp.Bytes:]))
	y := bn254.E2{
		A0: pyA0,
		A1: pyA1,
	}

	pzBytes := p.Z.ToBytesLittleEndian()
	pzA0, _ := fp.LittleEndian.Element((*[fp.Bytes]byte)(pzBytes[:fp.Bytes]))
	pzA1, _ := fp.LittleEndian.Element((*[fp.Bytes]byte)(pzBytes[fp.Bytes:]))
	z := bn254.E2{
		A0: pzA0,
		A1: pzA1,
	}

	var zSquared bn254.E2
	zSquared.Mul(&z, &z)

	var X bn254.E2
	X.Mul(&x, &z)

	var Y bn254.E2
	Y.Mul(&y, &zSquared)

	g2Jac := bn254.G2Jac{
		X: X,
		Y: Y,
		Z: z,
	}

	var g2Affine bn254.G2Affine
	return *g2Affine.FromJacobian(&g2Jac)
}
func HostSliceIcicleProjectiveToGnarkAffine(ps core.HostSlice[bn254_icicle.Projective], numWorker int) []bn254.G1Affine {
	output := make([]bn254.G1Affine, len(ps))

	if len(ps) < numWorker {
		numWorker = len(ps)
	}

	var wg sync.WaitGroup

	interval := int(math.Ceil(float64(len(ps)) / float64(numWorker)))

	for w := 0; w < numWorker; w++ {
		wg.Add(1)
		start := w * interval
		end := (w + 1) * interval
		if len(ps) < end {
			end = len(ps)
		}

		go func(workerStart, workerEnd int) {
			defer wg.Done()
			for i := workerStart; i < workerEnd; i++ {
				output[i] = IcicleProjectiveToGnarkAffine(ps[i])
			}

		}(start, end)
	}
	wg.Wait()
	return output
}

func ConvertFrToScalarFieldsBytesThread(data []fr.Element, numWorker int) []bn254_icicle.ScalarField {
	scalars := make([]bn254_icicle.ScalarField, len(data))

	if len(data) < numWorker {
		numWorker = len(data)
	}

	var wg sync.WaitGroup

	interval := int(math.Ceil(float64(len(data)) / float64(numWorker)))

	for w := 0; w < numWorker; w++ {
		wg.Add(1)
		start := w * interval
		end := (w + 1) * interval
		if len(data) < end {
			end = len(data)
		}

		go func(workerStart, workerEnd int) {
			defer wg.Done()
			output := ConvertFrToScalarFieldsBytes(data[workerStart:workerEnd])
			copy(scalars[workerStart:workerEnd], output[:])
		}(start, end)
	}
	wg.Wait()
	return scalars
}
