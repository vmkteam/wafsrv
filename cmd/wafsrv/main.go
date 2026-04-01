package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"wafsrv/internal/app"

	"github.com/namsral/flag"
	"github.com/vmkteam/embedlog"
)

const appName = "wafsrv"

var (
	fs           = flag.NewFlagSetWithEnvPrefix(os.Args[0], "WAFSRV", 0)
	flConfigPath = fs.String("config", "config.toml", "Path to config file")
	flVerbose    = fs.Bool("verbose", false, "enable debug output")
	flJSONLogs   = fs.Bool("json", false, "enable json output")
	flDev        = fs.Bool("dev", false, "enable dev mode")
)

func main() {
	flag.DefaultConfigFlagname = "config.flag"
	exitOnError(fs.Parse(os.Args[1:]))

	sl := embedlog.NewLogger(*flVerbose, *flJSONLogs)
	if *flDev {
		sl = embedlog.NewDevLogger()
	}
	slog.SetDefault(sl.Log())

	ctx := context.Background()
	sl.Print(ctx, "starting", "app", appName)

	cfg, err := app.LoadConfig(*flConfigPath)
	exitOnError(err)

	a, err := app.New(appName, sl, cfg)
	exitOnError(err)

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)

	go func() {
		if er := a.Run(ctx); er != nil && !errors.Is(er, http.ErrServerClosed) {
			sl.PrintOrErr(ctx, "server stopped", er)
			quit <- syscall.SIGTERM
		}
	}()

	<-quit

	sl.Print(ctx, "shutting down")

	if err = a.Shutdown(5 * time.Second); err != nil {
		sl.Error(ctx, "shutdown error", "err", err)
	}
}

func exitOnError(err error) {
	if err != nil {
		//nolint:sloglint
		slog.Error(err.Error())
		os.Exit(1)
	}
}
