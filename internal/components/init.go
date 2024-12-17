package components

import (
	"log/slog"
	"net/http"
	"os"

	"github.com/alexey-petrov/go-webauthn/gen/db/v1/dbv1connect"
	"github.com/alexey-petrov/go-webauthn/internal/grpcServer"
	"github.com/alexey-petrov/go-webauthn/internal/jwtService"
	"github.com/alexey-petrov/go-webauthn/internal/storage"
	"github.com/alexey-petrov/go-webauthn/pkg/logger/slogpretty"
)

const (
	envLocal = "local"
	envDev   = "dev"
	envProd  = "prod"
)

type Components struct {
	GrpcServer  *grpcServer.GrpcServer
	Storage     *storage.AuthStorage
	UserService *storage.UserService
	JwtService  *jwtService.JwtServiceStore
}

func InitComponents(logger *slog.Logger) (*Components, error) {

	// Connect to the database
	authStorage := storage.InitDB()

	userService := storage.NewUserService(authStorage)

	jwtServiceS := jwtService.New(logger, userService)

	erdTreeUrl := os.Getenv("ERDTREE_URL")

	if erdTreeUrl == "" {
		erdTreeUrl = os.Getenv("ERDTREE_LOCAL_URL")
	}

	erdtreeClient := dbv1connect.NewErdtreeStoreClient(
		http.DefaultClient,
		erdTreeUrl, // Server URL
	)

	grpcServer, _ := grpcServer.New(logger, userService, jwtServiceS, erdtreeClient)

	return &Components{
		GrpcServer:  grpcServer,
		Storage:     authStorage,
		UserService: userService,
		JwtService:  jwtServiceS,
	}, nil

}

func (c *Components) Shutdown() {
	c.GrpcServer.Stop()
}

func SetupLogger(env string) *slog.Logger {
	var logger *slog.Logger = slog.New(
		slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}),
	)

	switch env {
	case envLocal:
		logger = slogpretty.SetupPrettySlog()
	case envDev:
		logger = slog.New(
			slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}),
		)
	case envProd:
		logger = slog.New(
			slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}),
		)
	}

	return logger
}
