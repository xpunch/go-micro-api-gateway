package main

import (
	"github.com/urfave/cli/v2"
)

var (
	name = "go.micro.api.gateway"

	description = "go-micro api gateway"

	version = "1.0.0"

	flags = []cli.Flag{
		&cli.StringFlag{
			Name:    "address",
			Usage:   "Set the api address e.g 0.0.0.0:8080",
			EnvVars: []string{"MICRO_API_ADDRESS"},
		},
		&cli.StringFlag{
			Name:    "handler",
			Usage:   "Specify the request handler to be used for mapping HTTP requests to services; {api, event, http, rpc}",
			EnvVars: []string{"MICRO_API_HANDLER"},
		},
		&cli.StringFlag{
			Name:    "namespace",
			Usage:   "Set the namespace used by the API e.g. com.example",
			EnvVars: []string{"MICRO_API_NAMESPACE"},
		},
		&cli.StringFlag{
			Name:    "type",
			Usage:   "Set the service type used by the API e.g. api",
			EnvVars: []string{"MICRO_API_TYPE"},
		},
		&cli.StringFlag{
			Name:    "resolver",
			Usage:   "Set the hostname resolver used by the API {host, path, grpc}",
			EnvVars: []string{"MICRO_API_RESOLVER"},
		},
		&cli.BoolFlag{
			Name:    "enable_rpc",
			Usage:   "Enable call the backend directly via /rpc",
			EnvVars: []string{"MICRO_API_ENABLE_RPC"},
		},
		&cli.BoolFlag{
			Name:    "enable_cors",
			Usage:   "Enable CORS, allowing the API to be called by frontend applications",
			EnvVars: []string{"MICRO_API_ENABLE_CORS"},
			Value:   true,
		},
	}
)

type Options struct {
	Name                  string
	Namespace             string
	Address               string
	Handler               string
	Type                  string
	Resolver              string
	EnableACME            bool
	ACMEProvider          string
	ACMEChallengeProvider string
	ACMEHosts             []string
	EnableTLS             bool
	EnableRPC             bool
	EnableCors            bool
	EnableStats           bool
}
