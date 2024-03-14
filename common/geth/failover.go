package geth

import (
	"sync"

	"github.com/Layr-Labs/eigensdk-go/logging"
)

type FailoverController struct {
	NumberFault     uint64
	NumberSuccess   uint64
	currentRPCIndex int
	NumRPCClient    int
	Logger          logging.Logger
	mu              *sync.Mutex
}

func NewFailoverController(numRPCClient int, logger logging.Logger) *FailoverController {
	return &FailoverController{
		NumberFault:     0,
		NumberSuccess:   0,
		NumRPCClient:    numRPCClient,
		currentRPCIndex: 0,
		Logger:          logger,
		mu:              &sync.Mutex{},
	}
}

// To use the Failover controller, one must insert this function
// after every call that uses RPC.
// This function attribute the error and update statistics
func (f *FailoverController) ProcessError(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err == nil {
		f.NumberSuccess += 1
		return
	}

	fault := HandleError(err)
	if fault == EVMFault {
		return
	} else {
		// attribute anything else to server fault for rotation
		f.updateRPCFault(err)
		return
	}
}

// update rpc fault
func (f *FailoverController) updateRPCFault(err error) {
	f.NumberFault += 1
	f.Logger.Error("RPC fault", "error", err)
}

func (f *FailoverController) GetTotalNumberFault() uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.NumberFault
}