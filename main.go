package main

import (
	"os"

	"github.com/asim/go-micro/v3/logger"
	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:        name,
		Description: description,
		Version:     version,
		Flags:       flags,
		Action:      Run,
	}
	if err := app.Run(os.Args); err != nil {
		logger.Fatal(err)
	}
}
