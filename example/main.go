// Command example is a small, realistic Go program used to demo goup.
// Its go.mod deliberately pins outdated dependency versions — including
// golang.org/x/text v0.3.7, which has known vulnerabilities — so
// `make example` has something meaningful to show.
package main

import (
	"fmt"
	"os"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"github.com/rs/zerolog"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"golang.org/x/text/language"
)

func main() {
	log := logrus.New()
	log.Info("starting example", "id", uuid.New().String())

	_ = zerolog.Nop()
	_ = assert.New(nil)
	_ = language.English
	_ = godotenv.Load

	cmd := &cobra.Command{Use: "example", Run: func(*cobra.Command, []string) {
		fmt.Println("example ok")
	}}
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
