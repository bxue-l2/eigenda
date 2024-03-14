package geth

import (
	"github.com/Layr-Labs/eigenda/common"
	"github.com/urfave/cli"
)

var (
	rpcUrlFlagName           = "chain.rpc"
	privateKeyFlagName       = "chain.private-key"
	numConfirmationsFlagName = "chain.num-confirmations"
	numRetriesFlagName       = "chain.num-retries"
)

type EthClientConfig struct {
	RPCURLs          []string
	PrivateKeyString string
	NumConfirmations int
	NumRetries       int
}

func EthClientFlags(envPrefix string) []cli.Flag {
	return []cli.Flag{
		cli.StringSliceFlag{
			Name:     rpcUrlFlagName,
			Usage:    "Chain rpc. Disperser/Batcher can accept multiple. Node accepts one",
			Required: true,
			EnvVar:   common.PrefixEnvVar(envPrefix, "CHAIN_RPC"),
		},
		cli.StringFlag{
			Name:     privateKeyFlagName,
			Usage:    "Ethereum private key for disperser",
			Required: true,
			EnvVar:   common.PrefixEnvVar(envPrefix, "PRIVATE_KEY"),
		},
		cli.IntFlag{
			Name:     numConfirmationsFlagName,
			Usage:    "Number of confirmations to wait for",
			Required: false,
			Value:    0,
			EnvVar:   common.PrefixEnvVar(envPrefix, "NUM_CONFIRMATIONS"),
		},
		cli.IntFlag{
			Name:     numRetriesFlagName,
			Usage:    "Number of maximal retry for each rpc call",
			Required: false,
			Value:    2,
			EnvVar:   common.PrefixEnvVar(envPrefix, "NUM_RETRIES"),
		},
	}
}

func ReadEthClientConfig(ctx *cli.Context) EthClientConfig {
	cfg := EthClientConfig{}
	cfg.RPCURLs = ctx.GlobalStringSlice(rpcUrlFlagName)
	cfg.PrivateKeyString = ctx.GlobalString(privateKeyFlagName)
	cfg.NumConfirmations = ctx.GlobalInt(numConfirmationsFlagName)
	cfg.NumRetries = ctx.GlobalInt(numRetriesFlagName)
	return cfg
}

// ReadEthClientConfigRPCOnly doesn't read private key from flag.
// The private key for Node should be read from encrypted key file.
func ReadEthClientConfigRPCOnly(ctx *cli.Context) EthClientConfig {
	cfg := EthClientConfig{}
	cfg.RPCURLs = ctx.GlobalStringSlice(rpcUrlFlagName)
	cfg.NumConfirmations = ctx.GlobalInt(numConfirmationsFlagName)
	cfg.NumRetries = ctx.GlobalInt(numRetriesFlagName)
	return cfg
}
