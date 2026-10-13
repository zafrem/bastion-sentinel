package server

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	sentinelv1 "github.com/zafrem/bastion-sentinel/proto"
)

// grpcPublicMethods stay reachable without a token so orchestrators can probe health.
var grpcPublicMethods = map[string]bool{
	sentinelv1.SentinelService_Health_FullMethodName: true,
}

// authToken returns the configured shared token (config first, then env).
func (g *GRPC) authToken() string {
	g.mu.RLock()
	tok := g.cfg.Server.AuthToken
	g.mu.RUnlock()
	return resolveAuthToken(tok)
}

// checkAuth enforces the shared bearer token for one call. With no token
// configured the validation RPCs stay open, matching the REST behaviour.
func (g *GRPC) checkAuth(ctx context.Context, fullMethod string) error {
	if grpcPublicMethods[fullMethod] {
		return nil
	}
	token := g.authToken()
	if token == "" {
		return nil
	}
	md, _ := metadata.FromIncomingContext(ctx)
	for _, h := range md.Get("authorization") {
		if tokenMatches(h, token) {
			return nil
		}
	}
	return status.Error(codes.Unauthenticated, "missing or invalid bearer token")
}

func (g *GRPC) authUnaryInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	if err := g.checkAuth(ctx, info.FullMethod); err != nil {
		return nil, err
	}
	return handler(ctx, req)
}

func (g *GRPC) authStreamInterceptor(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	if err := g.checkAuth(ss.Context(), info.FullMethod); err != nil {
		return err
	}
	return handler(srv, ss)
}
