package main

import (
	"bufio"
	"fmt"
	"log"
	"math"
	"math/rand"
	"os"

	"runtime"
	"time"

	rs "github.com/Layr-Labs/eigenda/pkg/encoding/encoder"
	kzgRs "github.com/Layr-Labs/eigenda/pkg/encoding/kzgEncoder"

	//kzg "github.com/Layr-Labs/eigenda/pkg/kzg"
	bls "github.com/Layr-Labs/eigenda/pkg/kzg/bn254"
)

func main() {
	// TestKzgRs()
	//err := kzg.WriteGeneratorPoints(4194304)
	//if err != nil {
	//	log.Println("WriteGeneratorPoints failed:", err)
	//}
	PrecomputeSRS()
}

func PrecomputeSRS() {
	numSymbolList := []int{2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536} //, 131072
	//numSymbolList := []int{2, 4, 8, 16, 32, 64, 128, 256, 512, 1024}
	numNodeList := make([]uint64, 0)
	power := 16 // 2^16 = 65536
	numNode := uint64(1)
	for i := 1; i <= power; i++ {
		numNode = numNode * 2
		numNodeList = append(numNodeList, numNode)
	}

	fmt.Println("numNodeList", numNodeList)

	kzgConfig := &kzgRs.KzgConfig{
		G1Path:    "srs-store/g1.point.4194304",
		G2Path:    "srs-store/g2.point.4194304",
		CacheDir:  "SRSTables",
		SRSOrder:  4194304,
		NumWorker: uint64(runtime.GOMAXPROCS(0)),
	}

	// create encoding object
	kzgGroup, _ := kzgRs.NewKzgEncoderGroup(kzgConfig)
	f, err := os.Create("error_log")
	if err != nil {
		fmt.Println("failed to create file")
		return
	}
	w := bufio.NewWriter(f)

	for _, numNode := range numNodeList {
		numSys := numNode / 2
		for _, numSymbols := range numSymbolList {
			err := SetupKzgRs(numNode, numSys, numSymbols, kzgGroup)
			if err != nil {
				fmt.Println("error SetupKzgRs", err)
				w.WriteString(fmt.Sprintln(err))
			}
		}
	}

}

func SetupKzgRs(numNode, numSys uint64, numSymbols int, kzgGroup *kzgRs.KzgEncoderGroup) error {
	numPar := numNode - numSys
	ChunkLen := uint64(numSymbols) * numNode / numSys
	// Prepare data
	fmt.Printf("* Task Starts\n")
	fmt.Printf("    Num Sys: %v\n", numSys)
	fmt.Printf("    Num Par: %v\n", numPar)
	//fmt.Printf("    Data size(byte): %v\n", len(inputBytes))

	params := rs.EncodingParams{NumChunks: numNode, ChunkLen: ChunkLen}
	_, err := kzgGroup.NewKzgEncoder(params)
	if err != nil {
		return err
	}
	return nil
}

func TestKzgRs(numNode, numSys uint64, numSymbols int) {
	//numSymbols := 3
	// encode parameters
	//numNode := uint64(4) // 200
	//numSys := uint64(2)  // 180
	numPar := numNode - numSys
	ChunkLen := uint64(numSymbols) * numNode / numSys
	// Prepare data
	fmt.Printf("* Task Starts\n")
	fmt.Printf("    Num Sys: %v\n", numSys)
	fmt.Printf("    Num Par: %v\n", numPar)
	//fmt.Printf("    Data size(byte): %v\n", len(inputBytes))

	kzgConfig := &kzgRs.KzgConfig{
		G1Path:    "g1.point.30000",
		G2Path:    "g2.point.30000",
		CacheDir:  "SRSTables",
		SRSOrder:  30000,
		NumWorker: uint64(runtime.GOMAXPROCS(0)),
	}

	// create encoding object
	kzgGroup, _ := kzgRs.NewKzgEncoderGroup(kzgConfig)

	params := rs.EncodingParams{NumChunks: numNode, ChunkLen: ChunkLen}
	enc, _ := kzgGroup.NewKzgEncoder(params)

	//inputFr := kzgRs.ToFrArray(inputBytes)
	inputSize := uint64(numSymbols)
	inputFr := make([]bls.Fr, inputSize)
	for i := uint64(0); i < inputSize; i++ {
		bls.AsFr(&inputFr[i], i+1)
	}

	fmt.Printf("Input \n")
	printFr(inputFr)

	//inputSize := uint64(len(inputFr))
	commit, lowDegreeProof, frames, fIndices, err := enc.Encode(inputFr)
	_ = lowDegreeProof

	if err != nil {
		log.Fatal(err)
	}
	// Optionally verify
	startVerify := time.Now()

	//os.Exit(0)
	for i := 0; i < len(frames); i++ {
		//for i, f := range frames {
		f := frames[i]
		j := fIndices[i]
		q, err := rs.GetLeadingCosetIndex(uint64(i), numSys+numPar)
		if err != nil {
			log.Fatalf("%v", err)
		}

		if j != q {
			log.Fatal("leading coset inconsistency")
		}

		fmt.Printf("frame %v leading coset %v\n", i, j)
		lc := enc.Fs.ExpandedRootsOfUnity[uint64(j)]
		ok := f.Verify(enc.Ks, commit, &lc)
		if !ok {
			log.Fatalf("Proof %v failed\n", i)
		}
	}
	fmt.Printf("* Verify %v frames -> all correct. together using %v\n",
		len(frames), time.Since(startVerify))
	// sample some frames
	samples, indices := SampleFrames(frames, uint64(len(frames)-3))
	//samples, indices := SampleFrames(frames, numSys)
	//fmt.Printf("* Sampled %v frames\n", numSys)
	//// Decode data from samples

	dataFr, err := enc.Decode(samples, indices, inputSize)
	if err != nil {
		log.Fatal(err)
	}

	//printFr(dataFr)
	//dataFr, err := kzgRs.DecodeSys(samples, indices, inputSize)
	//if err != nil {
	//log.Fatalf("%v", err)
	//}

	fmt.Println(dataFr)
	// printFr(dataFr)
	//deData := kzgRs.ToByteArray(dataFr, inputByteSize)
	//fmt.Println("dataFr")
	// printFr(dataFr)
	//fmt.Println(deData)
	// Verify data is original in Fr
	//compareData(inputFr, dataFr)
	// Verify data is original in Byte
	//compareDataByte(deData, inputBytes)
	//fmt.Printf("* Compared original %v bytes with reconstructed -> PASS\n", inputByteSize)
	//_ = deData
}

// func getData(inputSize uint64) []bls.Fr {
// 	inputFr := make([]bls.Fr, inputSize)
// 	for i := uint64(0); i < inputSize; i++ {
// 		bls.AsFr(&inputFr[i], i+1)
// 	}
// 	return inputFr
// }
//
// func compareData(inputFr, dataFr []bls.Fr) {
// 	if len(inputFr) != len(dataFr) {
// 		log.Fatalf("Error. Diff length. input %v, data %v\n", len(inputFr), len(dataFr))
// 	}
//
// 	for i := 0; i < len(inputFr); i++ {
// 		if !bls.EqualFr(&inputFr[i], &dataFr[i]) {
// 			log.Fatalf("Error. Diff value at %v. input %v, data %v\n",
// 				i, inputFr[i].String(), dataFr[i].String())
// 		}
// 	}
// }
//
// func compareDataByte(inputFr, dataFr []byte) {
// 	if len(inputFr) != len(dataFr) {
// 		log.Fatalf("Error. Diff length. input %v, data %v\n", len(inputFr), len(dataFr))
// 	}
//
// 	for i := 0; i < len(inputFr); i++ {
// 		if inputFr[i] != dataFr[i] {
// 			log.Fatalf("Error. Diff Data byte value at %v. input %v, data %v\n",
// 				i, inputFr[i:], dataFr[i:])
// 		}
// 	}
// }
//
// func initPoly(size int) ([]bls.Fr, []bls.Fr) {
// 	v := make([]uint64, size)
// 	for i := 0; i < size; i++ {
// 		v[i] = uint64(i + 1)
// 	}
// 	polyFr := makeFr(v)
// 	fs := kzg.NewFFTSettings(3)
// 	dataFr, _ := fs.FFT(polyFr, false)
// 	return polyFr, dataFr
// }
//
// func initData(size uint64) ([]bls.Fr, []bls.Fr) {
// 	v := make([]uint64, size)
// 	for i := uint64(0); i < size; i++ {
// 		v[i] = uint64(i + 1)
// 	}
// 	dataFr := makeFr(v)
// 	order := kzgRs.CeilIntPowerOf2Num(size)
// 	fs := kzg.NewFFTSettings(uint8(order))
// 	polyFr, err := fs.FFT(dataFr, true)
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	return polyFr, dataFr
// }
//
// func makeFr(input []uint64) []bls.Fr {
// 	inputFr := make([]bls.Fr, len(input))
// 	for i := 0; i < len(input); i++ {
// 		bls.AsFr(&inputFr[i], input[i])
// 	}
// 	return inputFr
// }

func printFr(d []bls.Fr) {
	for _, e := range d {
		fmt.Printf("%v ", e.String())
	}
	fmt.Printf("\n")
}

// func printG1(d []bls.G1Point) {
// 	for i, e := range d {
// 		fmt.Printf("%v: %v \n", i, e.String())
// 	}
// 	fmt.Printf("\n")
// }

func SampleFrames(frames []kzgRs.Frame, num uint64) ([]kzgRs.Frame, []uint64) {
	samples := make([]kzgRs.Frame, num)
	indices := rand.Perm(len(frames))
	indices = indices[:num]

	frameIndices := make([]uint64, num)
	for i, j := range indices {
		samples[i] = frames[j]
		frameIndices[i] = uint64(j)
	}
	return samples, frameIndices
}

func RoundUpDivision(a, b uint64) uint64 {
	if b == 0 {
		log.Fatal("Cannot divide 0")
	}
	return uint64(math.Ceil(float64(a) / float64(b)))
}

// func genText(M uint64) []byte {
// 	signal := make([]byte, M)
// 	rand.Seed(time.Now().UnixNano())
// 	for i := uint64(0); i < M; i++ {
// 		r := rand.Intn(128)
// 		signal[i] = byte(r)
// 	}
// 	return signal
// }
