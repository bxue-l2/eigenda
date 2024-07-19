package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/Layr-Labs/eigenda/common"

	"github.com/Layr-Labs/eigenda/disperser/cmd/encoder/flags"
	"github.com/urfave/cli"

	_ "net/http/pprof"
)

var (
	// Version is the version of the binary.
	Version   string
	GitCommit string
	GitDate   string
)

func main() {

	app := cli.NewApp()
	app.Flags = flags.Flags
	app.Version = fmt.Sprintf("%s-%s-%s", Version, GitCommit, GitDate)
	app.Name = "encoder"
	app.Usage = "EigenDA Encoder"
	app.Description = "Service for encoding blobs"

	app.Action = RunEncoderServer
	err := app.Run(os.Args)
	if err != nil {
		log.Fatalf("application failed: %v", err)
	}

	select {}
}

func RunEncoderServer(ctx *cli.Context) error {

	config, err := NewConfig(ctx)
	if err != nil {
		return err
	}

	logger, err := common.NewLogger(config.LoggerConfig)
	if err != nil {
		return err
	}

	enc, err := NewEncoderGRPCServer(config, logger)
	if err != nil {
		return err
	}
	defer enc.Close()

	// Start pprof
	go func() {
		http.ListenAndServe(":6060", nil)
	}()

	err = enc.Start(context.Background())
	if err != nil {
		return err
	}

	return nil
}
