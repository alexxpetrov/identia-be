// Code generated by protoc-gen-connect-go. DO NOT EDIT.
//
// Source: auth/v1/auth.proto

package authv1connect

import (
	connect "connectrpc.com/connect"
	context "context"
	errors "errors"
	v1 "github.com/alexey-petrov/go-webauthn/gen/auth/v1"
	http "net/http"
	strings "strings"
)

// This is a compile-time assertion to ensure that this generated file and the connect package are
// compatible. If you get a compiler error that this constant is not defined, this code was
// generated with a version of connect newer than the one compiled into your binary. You can fix the
// problem by either regenerating this code with an older version of connect or updating the connect
// version compiled into your binary.
const _ = connect.IsAtLeastVersion1_13_0

const (
	// AuthServiceName is the fully-qualified name of the AuthService service.
	AuthServiceName = "auth.v1.AuthService"
)

// These constants are the fully-qualified names of the RPCs defined in this package. They're
// exposed at runtime as Spec.Procedure and as the final two segments of the HTTP route.
//
// Note that these are different from the fully-qualified method names used by
// google.golang.org/protobuf/reflect/protoreflect. To convert from these constants to
// reflection-formatted method names, remove the leading slash and convert the remaining slash to a
// period.
const (
	// AuthServiceLoginProcedure is the fully-qualified name of the AuthService's Login RPC.
	AuthServiceLoginProcedure = "/auth.v1.AuthService/Login"
	// AuthServiceRegisterProcedure is the fully-qualified name of the AuthService's Register RPC.
	AuthServiceRegisterProcedure = "/auth.v1.AuthService/Register"
	// AuthServiceBeginRegistrationProcedure is the fully-qualified name of the AuthService's
	// BeginRegistration RPC.
	AuthServiceBeginRegistrationProcedure = "/auth.v1.AuthService/BeginRegistration"
	// AuthServiceFinishRegistrationProcedure is the fully-qualified name of the AuthService's
	// FinishRegistration RPC.
	AuthServiceFinishRegistrationProcedure = "/auth.v1.AuthService/FinishRegistration"
	// AuthServiceBeginLoginProcedure is the fully-qualified name of the AuthService's BeginLogin RPC.
	AuthServiceBeginLoginProcedure = "/auth.v1.AuthService/BeginLogin"
	// AuthServiceFinishLoginProcedure is the fully-qualified name of the AuthService's FinishLogin RPC.
	AuthServiceFinishLoginProcedure = "/auth.v1.AuthService/FinishLogin"
	// AuthServiceRefreshAccessTokenProcedure is the fully-qualified name of the AuthService's
	// RefreshAccessToken RPC.
	AuthServiceRefreshAccessTokenProcedure = "/auth.v1.AuthService/RefreshAccessToken"
	// AuthServiceLogoutProcedure is the fully-qualified name of the AuthService's Logout RPC.
	AuthServiceLogoutProcedure = "/auth.v1.AuthService/Logout"
)

// These variables are the protoreflect.Descriptor objects for the RPCs defined in this package.
var (
	authServiceServiceDescriptor                  = v1.File_auth_v1_auth_proto.Services().ByName("AuthService")
	authServiceLoginMethodDescriptor              = authServiceServiceDescriptor.Methods().ByName("Login")
	authServiceRegisterMethodDescriptor           = authServiceServiceDescriptor.Methods().ByName("Register")
	authServiceBeginRegistrationMethodDescriptor  = authServiceServiceDescriptor.Methods().ByName("BeginRegistration")
	authServiceFinishRegistrationMethodDescriptor = authServiceServiceDescriptor.Methods().ByName("FinishRegistration")
	authServiceBeginLoginMethodDescriptor         = authServiceServiceDescriptor.Methods().ByName("BeginLogin")
	authServiceFinishLoginMethodDescriptor        = authServiceServiceDescriptor.Methods().ByName("FinishLogin")
	authServiceRefreshAccessTokenMethodDescriptor = authServiceServiceDescriptor.Methods().ByName("RefreshAccessToken")
	authServiceLogoutMethodDescriptor             = authServiceServiceDescriptor.Methods().ByName("Logout")
)

// AuthServiceClient is a client for the auth.v1.AuthService service.
type AuthServiceClient interface {
	Login(context.Context, *connect.Request[v1.LoginRequest]) (*connect.Response[v1.LoginResponse], error)
	Register(context.Context, *connect.Request[v1.RegisterRequest]) (*connect.Response[v1.RegisterResponse], error)
	BeginRegistration(context.Context, *connect.Request[v1.BeginRegistrationRequest]) (*connect.Response[v1.BeginRegistrationResponse], error)
	FinishRegistration(context.Context, *connect.Request[v1.FinishRegistrationRequest]) (*connect.Response[v1.FinishRegistrationResponse], error)
	BeginLogin(context.Context, *connect.Request[v1.BeginLoginRequest]) (*connect.Response[v1.BeginLoginResponse], error)
	FinishLogin(context.Context, *connect.Request[v1.FinishLoginRequest]) (*connect.Response[v1.FinishLoginResponse], error)
	RefreshAccessToken(context.Context, *connect.Request[v1.RefreshAccessTokenRequest]) (*connect.Response[v1.RefreshAccessTokenResponse], error)
	Logout(context.Context, *connect.Request[v1.LogoutRequest]) (*connect.Response[v1.LogoutResponse], error)
}

// NewAuthServiceClient constructs a client for the auth.v1.AuthService service. By default, it uses
// the Connect protocol with the binary Protobuf Codec, asks for gzipped responses, and sends
// uncompressed requests. To use the gRPC or gRPC-Web protocols, supply the connect.WithGRPC() or
// connect.WithGRPCWeb() options.
//
// The URL supplied here should be the base URL for the Connect or gRPC server (for example,
// http://api.acme.com or https://acme.com/grpc).
func NewAuthServiceClient(httpClient connect.HTTPClient, baseURL string, opts ...connect.ClientOption) AuthServiceClient {
	baseURL = strings.TrimRight(baseURL, "/")
	return &authServiceClient{
		login: connect.NewClient[v1.LoginRequest, v1.LoginResponse](
			httpClient,
			baseURL+AuthServiceLoginProcedure,
			connect.WithSchema(authServiceLoginMethodDescriptor),
			connect.WithClientOptions(opts...),
		),
		register: connect.NewClient[v1.RegisterRequest, v1.RegisterResponse](
			httpClient,
			baseURL+AuthServiceRegisterProcedure,
			connect.WithSchema(authServiceRegisterMethodDescriptor),
			connect.WithClientOptions(opts...),
		),
		beginRegistration: connect.NewClient[v1.BeginRegistrationRequest, v1.BeginRegistrationResponse](
			httpClient,
			baseURL+AuthServiceBeginRegistrationProcedure,
			connect.WithSchema(authServiceBeginRegistrationMethodDescriptor),
			connect.WithClientOptions(opts...),
		),
		finishRegistration: connect.NewClient[v1.FinishRegistrationRequest, v1.FinishRegistrationResponse](
			httpClient,
			baseURL+AuthServiceFinishRegistrationProcedure,
			connect.WithSchema(authServiceFinishRegistrationMethodDescriptor),
			connect.WithClientOptions(opts...),
		),
		beginLogin: connect.NewClient[v1.BeginLoginRequest, v1.BeginLoginResponse](
			httpClient,
			baseURL+AuthServiceBeginLoginProcedure,
			connect.WithSchema(authServiceBeginLoginMethodDescriptor),
			connect.WithClientOptions(opts...),
		),
		finishLogin: connect.NewClient[v1.FinishLoginRequest, v1.FinishLoginResponse](
			httpClient,
			baseURL+AuthServiceFinishLoginProcedure,
			connect.WithSchema(authServiceFinishLoginMethodDescriptor),
			connect.WithClientOptions(opts...),
		),
		refreshAccessToken: connect.NewClient[v1.RefreshAccessTokenRequest, v1.RefreshAccessTokenResponse](
			httpClient,
			baseURL+AuthServiceRefreshAccessTokenProcedure,
			connect.WithSchema(authServiceRefreshAccessTokenMethodDescriptor),
			connect.WithClientOptions(opts...),
		),
		logout: connect.NewClient[v1.LogoutRequest, v1.LogoutResponse](
			httpClient,
			baseURL+AuthServiceLogoutProcedure,
			connect.WithSchema(authServiceLogoutMethodDescriptor),
			connect.WithClientOptions(opts...),
		),
	}
}

// authServiceClient implements AuthServiceClient.
type authServiceClient struct {
	login              *connect.Client[v1.LoginRequest, v1.LoginResponse]
	register           *connect.Client[v1.RegisterRequest, v1.RegisterResponse]
	beginRegistration  *connect.Client[v1.BeginRegistrationRequest, v1.BeginRegistrationResponse]
	finishRegistration *connect.Client[v1.FinishRegistrationRequest, v1.FinishRegistrationResponse]
	beginLogin         *connect.Client[v1.BeginLoginRequest, v1.BeginLoginResponse]
	finishLogin        *connect.Client[v1.FinishLoginRequest, v1.FinishLoginResponse]
	refreshAccessToken *connect.Client[v1.RefreshAccessTokenRequest, v1.RefreshAccessTokenResponse]
	logout             *connect.Client[v1.LogoutRequest, v1.LogoutResponse]
}

// Login calls auth.v1.AuthService.Login.
func (c *authServiceClient) Login(ctx context.Context, req *connect.Request[v1.LoginRequest]) (*connect.Response[v1.LoginResponse], error) {
	return c.login.CallUnary(ctx, req)
}

// Register calls auth.v1.AuthService.Register.
func (c *authServiceClient) Register(ctx context.Context, req *connect.Request[v1.RegisterRequest]) (*connect.Response[v1.RegisterResponse], error) {
	return c.register.CallUnary(ctx, req)
}

// BeginRegistration calls auth.v1.AuthService.BeginRegistration.
func (c *authServiceClient) BeginRegistration(ctx context.Context, req *connect.Request[v1.BeginRegistrationRequest]) (*connect.Response[v1.BeginRegistrationResponse], error) {
	return c.beginRegistration.CallUnary(ctx, req)
}

// FinishRegistration calls auth.v1.AuthService.FinishRegistration.
func (c *authServiceClient) FinishRegistration(ctx context.Context, req *connect.Request[v1.FinishRegistrationRequest]) (*connect.Response[v1.FinishRegistrationResponse], error) {
	return c.finishRegistration.CallUnary(ctx, req)
}

// BeginLogin calls auth.v1.AuthService.BeginLogin.
func (c *authServiceClient) BeginLogin(ctx context.Context, req *connect.Request[v1.BeginLoginRequest]) (*connect.Response[v1.BeginLoginResponse], error) {
	return c.beginLogin.CallUnary(ctx, req)
}

// FinishLogin calls auth.v1.AuthService.FinishLogin.
func (c *authServiceClient) FinishLogin(ctx context.Context, req *connect.Request[v1.FinishLoginRequest]) (*connect.Response[v1.FinishLoginResponse], error) {
	return c.finishLogin.CallUnary(ctx, req)
}

// RefreshAccessToken calls auth.v1.AuthService.RefreshAccessToken.
func (c *authServiceClient) RefreshAccessToken(ctx context.Context, req *connect.Request[v1.RefreshAccessTokenRequest]) (*connect.Response[v1.RefreshAccessTokenResponse], error) {
	return c.refreshAccessToken.CallUnary(ctx, req)
}

// Logout calls auth.v1.AuthService.Logout.
func (c *authServiceClient) Logout(ctx context.Context, req *connect.Request[v1.LogoutRequest]) (*connect.Response[v1.LogoutResponse], error) {
	return c.logout.CallUnary(ctx, req)
}

// AuthServiceHandler is an implementation of the auth.v1.AuthService service.
type AuthServiceHandler interface {
	Login(context.Context, *connect.Request[v1.LoginRequest]) (*connect.Response[v1.LoginResponse], error)
	Register(context.Context, *connect.Request[v1.RegisterRequest]) (*connect.Response[v1.RegisterResponse], error)
	BeginRegistration(context.Context, *connect.Request[v1.BeginRegistrationRequest]) (*connect.Response[v1.BeginRegistrationResponse], error)
	FinishRegistration(context.Context, *connect.Request[v1.FinishRegistrationRequest]) (*connect.Response[v1.FinishRegistrationResponse], error)
	BeginLogin(context.Context, *connect.Request[v1.BeginLoginRequest]) (*connect.Response[v1.BeginLoginResponse], error)
	FinishLogin(context.Context, *connect.Request[v1.FinishLoginRequest]) (*connect.Response[v1.FinishLoginResponse], error)
	RefreshAccessToken(context.Context, *connect.Request[v1.RefreshAccessTokenRequest]) (*connect.Response[v1.RefreshAccessTokenResponse], error)
	Logout(context.Context, *connect.Request[v1.LogoutRequest]) (*connect.Response[v1.LogoutResponse], error)
}

// NewAuthServiceHandler builds an HTTP handler from the service implementation. It returns the path
// on which to mount the handler and the handler itself.
//
// By default, handlers support the Connect, gRPC, and gRPC-Web protocols with the binary Protobuf
// and JSON codecs. They also support gzip compression.
func NewAuthServiceHandler(svc AuthServiceHandler, opts ...connect.HandlerOption) (string, http.Handler) {
	authServiceLoginHandler := connect.NewUnaryHandler(
		AuthServiceLoginProcedure,
		svc.Login,
		connect.WithSchema(authServiceLoginMethodDescriptor),
		connect.WithHandlerOptions(opts...),
	)
	authServiceRegisterHandler := connect.NewUnaryHandler(
		AuthServiceRegisterProcedure,
		svc.Register,
		connect.WithSchema(authServiceRegisterMethodDescriptor),
		connect.WithHandlerOptions(opts...),
	)
	authServiceBeginRegistrationHandler := connect.NewUnaryHandler(
		AuthServiceBeginRegistrationProcedure,
		svc.BeginRegistration,
		connect.WithSchema(authServiceBeginRegistrationMethodDescriptor),
		connect.WithHandlerOptions(opts...),
	)
	authServiceFinishRegistrationHandler := connect.NewUnaryHandler(
		AuthServiceFinishRegistrationProcedure,
		svc.FinishRegistration,
		connect.WithSchema(authServiceFinishRegistrationMethodDescriptor),
		connect.WithHandlerOptions(opts...),
	)
	authServiceBeginLoginHandler := connect.NewUnaryHandler(
		AuthServiceBeginLoginProcedure,
		svc.BeginLogin,
		connect.WithSchema(authServiceBeginLoginMethodDescriptor),
		connect.WithHandlerOptions(opts...),
	)
	authServiceFinishLoginHandler := connect.NewUnaryHandler(
		AuthServiceFinishLoginProcedure,
		svc.FinishLogin,
		connect.WithSchema(authServiceFinishLoginMethodDescriptor),
		connect.WithHandlerOptions(opts...),
	)
	authServiceRefreshAccessTokenHandler := connect.NewUnaryHandler(
		AuthServiceRefreshAccessTokenProcedure,
		svc.RefreshAccessToken,
		connect.WithSchema(authServiceRefreshAccessTokenMethodDescriptor),
		connect.WithHandlerOptions(opts...),
	)
	authServiceLogoutHandler := connect.NewUnaryHandler(
		AuthServiceLogoutProcedure,
		svc.Logout,
		connect.WithSchema(authServiceLogoutMethodDescriptor),
		connect.WithHandlerOptions(opts...),
	)
	return "/auth.v1.AuthService/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case AuthServiceLoginProcedure:
			authServiceLoginHandler.ServeHTTP(w, r)
		case AuthServiceRegisterProcedure:
			authServiceRegisterHandler.ServeHTTP(w, r)
		case AuthServiceBeginRegistrationProcedure:
			authServiceBeginRegistrationHandler.ServeHTTP(w, r)
		case AuthServiceFinishRegistrationProcedure:
			authServiceFinishRegistrationHandler.ServeHTTP(w, r)
		case AuthServiceBeginLoginProcedure:
			authServiceBeginLoginHandler.ServeHTTP(w, r)
		case AuthServiceFinishLoginProcedure:
			authServiceFinishLoginHandler.ServeHTTP(w, r)
		case AuthServiceRefreshAccessTokenProcedure:
			authServiceRefreshAccessTokenHandler.ServeHTTP(w, r)
		case AuthServiceLogoutProcedure:
			authServiceLogoutHandler.ServeHTTP(w, r)
		default:
			http.NotFound(w, r)
		}
	})
}

// UnimplementedAuthServiceHandler returns CodeUnimplemented from all methods.
type UnimplementedAuthServiceHandler struct{}

func (UnimplementedAuthServiceHandler) Login(context.Context, *connect.Request[v1.LoginRequest]) (*connect.Response[v1.LoginResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("auth.v1.AuthService.Login is not implemented"))
}

func (UnimplementedAuthServiceHandler) Register(context.Context, *connect.Request[v1.RegisterRequest]) (*connect.Response[v1.RegisterResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("auth.v1.AuthService.Register is not implemented"))
}

func (UnimplementedAuthServiceHandler) BeginRegistration(context.Context, *connect.Request[v1.BeginRegistrationRequest]) (*connect.Response[v1.BeginRegistrationResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("auth.v1.AuthService.BeginRegistration is not implemented"))
}

func (UnimplementedAuthServiceHandler) FinishRegistration(context.Context, *connect.Request[v1.FinishRegistrationRequest]) (*connect.Response[v1.FinishRegistrationResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("auth.v1.AuthService.FinishRegistration is not implemented"))
}

func (UnimplementedAuthServiceHandler) BeginLogin(context.Context, *connect.Request[v1.BeginLoginRequest]) (*connect.Response[v1.BeginLoginResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("auth.v1.AuthService.BeginLogin is not implemented"))
}

func (UnimplementedAuthServiceHandler) FinishLogin(context.Context, *connect.Request[v1.FinishLoginRequest]) (*connect.Response[v1.FinishLoginResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("auth.v1.AuthService.FinishLogin is not implemented"))
}

func (UnimplementedAuthServiceHandler) RefreshAccessToken(context.Context, *connect.Request[v1.RefreshAccessTokenRequest]) (*connect.Response[v1.RefreshAccessTokenResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("auth.v1.AuthService.RefreshAccessToken is not implemented"))
}

func (UnimplementedAuthServiceHandler) Logout(context.Context, *connect.Request[v1.LogoutRequest]) (*connect.Response[v1.LogoutResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("auth.v1.AuthService.Logout is not implemented"))
}
