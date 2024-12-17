package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/alexey-petrov/go-webauthn/internal/components"
	"github.com/joho/godotenv"
	"golang.org/x/sync/errgroup"
)

func main() {
	err := godotenv.Load("../.env")
	if err != nil {
		fmt.Println("Error loading .env file")
	}

	env := os.Getenv("ENV")

	logger := components.SetupLogger(env)
	serverComponents, _ := components.InitComponents(logger)

	if err != nil {
		logger.Error("bad configuration. missing env file", slog.String("error", err.Error()))
		// os.Exit(1)
	}

	defer serverComponents.Shutdown()

	eg, ctx := errgroup.WithContext(context.Background())
	sigQuit := make(chan os.Signal, 1)
	signal.Notify(sigQuit, syscall.SIGINT, syscall.SIGTERM)

	eg.Go(func() error {
		return serverComponents.GrpcServer.Run(ctx)
	})

	eg.Go(func() error {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case s := <-sigQuit:
			logger.Info("Captured signal", slog.String("signal", s.String()))
			return fmt.Errorf("captured signal: %v", s)
		}
	})

	err = eg.Wait()
	logger.Info("Gracefully shutting down the servers", slog.String("error", err.Error()))
}
