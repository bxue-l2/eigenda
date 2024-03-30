package rs_test

import (
	"log"
	"math/rand"
	"os"
	"testing"

	"github.com/Layr-Labs/eigenda/encoding/rs"
)

const (
	BYTES_PER_COEFFICIENT = 31
)

var (
	GETTYSBURG_ADDRESS_BYTES      = []byte("Fourscore and seven years ago our fathers brought forth, on this continent, a new nation, conceived in liberty, and dedicated to the proposition that all men are created equal. Now we are engaged in a great civil war, testing whether that nation, or any nation so conceived, and so dedicated, can long endure. We are met on a great battle-field of that war. We have come to dedicate a portion of that field, as a final resting-place for those who here gave their lives, that that nation might live. It is altogether fitting and proper that we should do this. But, in a larger sense, we cannot dedicate, we cannot consecrate—we cannot hallow—this ground. The brave men, living and dead, who struggled here, have consecrated it far above our poor power to add or detract. The world will little note, nor long remember what we say here, but it can never forget what they did here. It is for us the living, rather, to be dedicated here to the unfinished work which they who fought here have thus far so nobly advanced. It is rather for us to be here dedicated to the great task remaining before us—that from these honored dead we take increased devotion to that cause for which they here gave the last full measure of devotion—that we here highly resolve that these dead shall not have died in vain—that this nation, under God, shall have a new birth of freedom, and that government of the people, by the people, for the people, shall not perish from the earth.")
	GETTYSBURG_ADDRESS_BYTES_IFFT = []byte{}
	numNode                       uint64
	numSys                        uint64
	numPar                        uint64
)

func setupSuite(t *testing.T) func(t *testing.T) {
	log.Println("Setting up suite")

	numNode = uint64(4)
	numSys = uint64(3)
	numPar = numNode - numSys

	GETTYSBURG_ADDRESS_BYTES_IFFT, _ = rs.ConvertByteEvalToPaddedCoeffs(GETTYSBURG_ADDRESS_BYTES)

	return func(t *testing.T) {
		log.Println("Tearing down suite")

		os.RemoveAll("./data")
	}

}

func sampleFrames(frames []rs.Frame, num uint64) ([]rs.Frame, []uint64) {
	samples := make([]rs.Frame, num)
	indices := rand.Perm(len(frames))
	indices = indices[:num]

	frameIndices := make([]uint64, num)
	for i, j := range indices {
		samples[i] = frames[j]
		frameIndices[i] = uint64(j)
	}
	return samples, frameIndices
}
