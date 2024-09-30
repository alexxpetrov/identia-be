package main

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"connectrpc.com/connect"
	"github.com/alexey-petrov/go-server/db"
	auth "github.com/alexey-petrov/go-webauthn/authService"
	"github.com/alexey-petrov/go-webauthn/gen/auth/v1/authv1connect"
	"github.com/alexey-petrov/go-webauthn/keys"
	"github.com/joho/godotenv"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

func NewAuthInterceptor() connect.UnaryInterceptorFunc {
	interceptor := func(next connect.UnaryFunc) connect.UnaryFunc {
		return connect.UnaryFunc(func(
			ctx context.Context,
			req connect.AnyRequest,
		) (connect.AnyResponse, error) {

			return next(ctx, req)
		})
	}
	return connect.UnaryInterceptorFunc(interceptor)
}

func main() {
	err := godotenv.Load()
	if err != nil {
		fmt.Println("Error loading .env file")
	}
	// Connect to the database
	db.InitDB()

	publicUrl := os.Getenv("PUBLIC_URL")

	auth := &auth.AuthServiceServer{}
	mux := http.NewServeMux()
	interceptors := connect.WithInterceptors(NewAuthInterceptor())
	path, handler := authv1connect.NewAuthServiceHandler(auth, interceptors)
	fmt.Println(publicUrl)
	corsHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if publicUrl != "" {
			w.Header().Set("Access-Control-Allow-Origin", publicUrl)

		} else {
			w.Header().Set("Access-Control-Allow-Origin", "http://localhost:3000")
		}
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, Set-Cookie, connect-protocol-version")
		w.Header().Set("Access-Control-Allow-Credentials", "true")

		if r.Method == "OPTIONS" {
			return
		}

		ctx := context.WithValue(r.Context(), keys.HttpRequestKey, keys.HttpRequestResponse{Request: r, Response: w})
		// Call the next handler with the updated context
		handler.ServeHTTP(w, r.WithContext(ctx))
	})
	fmt.Printf("ConnectRPC is serving at :%s\n", os.Getenv("PORT"))
	mux.Handle(path, corsHandler)

	http.ListenAndServe(
		":"+os.Getenv("PORT"),
		// Use h2c so we can serve HTTP/2 without TLS.
		h2c.NewHandler(mux, &http2.Server{}),
	)

}
