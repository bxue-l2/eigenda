package gpu

import (
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	icicle_bn254 "github.com/ingonyama-zk/icicle/v2/wrappers/golang/curves/bn254"
)

func ConvertFrToScalarFieldsBytes(data []fr.Element) []icicle_bn254.ScalarField {
	scalars := make([]icicle_bn254.ScalarField, len(data))

	for i := 0; i < len(data); i++ {
		src := data[i] // 4 uint64
		var littleEndian [32]byte

		fr.LittleEndian.PutElement(&littleEndian, src)
		scalars[i].FromBytesLittleEndian(littleEndian[:])
	}
	return scalars
}

func ConvertScalarFieldsToFrBytes(scalars []icicle_bn254.ScalarField) []fr.Element {
	frElements := make([]fr.Element, len(scalars))

	for i := 0; i < len(frElements); i++ {
		v := scalars[i]
		slice64, _ := fr.LittleEndian.Element((*[fr.Bytes]byte)(v.ToBytesLittleEndian()))
		frElements[i] = slice64
	}
	return frElements
}

func ProjectiveToGnarkAffine(p icicle_bn254.Projective) bn254.G1Affine {
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

// Very important, if want target to be projective, do not use this function. Use the one below
func BatchConvertGnarkAffineToIcicleAffine(gAffineList []bn254.G1Affine) []icicle_bn254.Affine {
	icicleAffineList := make([]icicle_bn254.Affine, len(gAffineList))
	for i := 0; i < len(gAffineList); i++ {
		GnarkAffineToIcicleAffine(&gAffineList[i], &icicleAffineList[i])
	}
	return icicleAffineList
}

func GnarkAffineToIcicleAffine(g1 *bn254.G1Affine, iciAffine *icicle_bn254.Affine) {
	var littleEndBytesX, littleEndBytesY [32]byte
	fp.LittleEndian.PutElement(&littleEndBytesX, g1.X)
	fp.LittleEndian.PutElement(&littleEndBytesY, g1.Y)

	iciAffine.X.FromBytesLittleEndian(littleEndBytesX[:])
	iciAffine.Y.FromBytesLittleEndian(littleEndBytesY[:])
}

func BatchConvertGnarkAffineToIcicleProjective(gAffineList []bn254.G1Affine) []icicle_bn254.Projective {
	icicleProjectiveList := make([]icicle_bn254.Projective, len(gAffineList))
	var icicleAffine icicle_bn254.Affine

	for i := 0; i < len(gAffineList); i++ {
		GnarkAffineToIcicleAffine(&gAffineList[i], &icicleAffine)
		icicleProjectiveList[i] = icicleAffine.ToProjective()
	}

	return icicleProjectiveList
}
