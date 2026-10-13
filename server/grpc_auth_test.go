package server_test

import (
	"context"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/zafrem/bastion-sentinel/cache"
	"github.com/zafrem/bastion-sentinel/config"
	"github.com/zafrem/bastion-sentinel/engine"
	sentinelv1 "github.com/zafrem/bastion-sentinel/proto"
	"github.com/zafrem/bastion-sentinel/server"
)

// startAuthGRPC serves a real Sentinel gRPC server over an in-memory listener so the
// interceptors run exactly as they do on the wire.
func startAuthGRPC(t *testing.T, token string) (sentinelv1.SentinelServiceClient, *grpc.ClientConn) {
	t.Helper()
	cfg := config.Default()
	cfg.Server.AuthToken = token
	eng, err := engine.New(cfg)
	if err != nil {
		t.Fatalf("engine.New: %v", err)
	}
	c, _ := cache.New(config.CacheConfig{Enabled: true, Type: "memory"})
	val := cache.NewCached(eng, c, time.Minute)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	g := server.NewGRPC(cfg, val, c, "", log, server.NewNotifier(cfg.Notifications, log))

	lis := bufconn.Listen(1 << 20)
	go func() { _ = g.Serve(lis) }()
	t.Cleanup(g.Shutdown)

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return sentinelv1.NewSentinelServiceClient(conn), conn
}

func withBearer(ctx context.Context, tok string) context.Context {
	return metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+tok)
}

func wantCode(t *testing.T, what string, err error, want codes.Code) {
	t.Helper()
	if got := status.Code(err); got != want {
		t.Errorf("%s: code = %v (err=%v), want %v", what, got, err, want)
	}
}

func TestGRPCAuth_OpenWhenNoTokenConfigured(t *testing.T) {
	cl, _ := startAuthGRPC(t, "")
	_, err := cl.Validate(context.Background(), validProtoRequest("What is AI?"))
	wantCode(t, "Validate without token (none configured)", err, codes.OK)
}

func TestGRPCAuth_UnaryRequiresToken(t *testing.T) {
	cl, _ := startAuthGRPC(t, "s3cret-token")
	req := validProtoRequest("What is AI?")

	_, err := cl.Validate(context.Background(), req)
	wantCode(t, "missing token", err, codes.Unauthenticated)

	_, err = cl.Validate(withBearer(context.Background(), "wrong"), req)
	wantCode(t, "wrong token", err, codes.Unauthenticated)

	_, err = cl.Validate(metadata.AppendToOutgoingContext(context.Background(), "authorization", "Basic s3cret-token"), req)
	wantCode(t, "wrong scheme", err, codes.Unauthenticated)

	_, err = cl.Validate(withBearer(context.Background(), "s3cret-token"), req)
	wantCode(t, "correct token", err, codes.OK)

	_, err = cl.ValidateBatch(context.Background(), &sentinelv1.BatchRequest{})
	wantCode(t, "batch without token", err, codes.Unauthenticated)
}

func TestGRPCAuth_HealthStaysPublic(t *testing.T) {
	cl, _ := startAuthGRPC(t, "s3cret-token")
	_, err := cl.Health(context.Background(), &sentinelv1.HealthRequest{})
	wantCode(t, "Health without token", err, codes.OK)
}

func TestGRPCAuth_StreamsRequireToken(t *testing.T) {
	_, conn := startAuthGRPC(t, "s3cret-token")
	desc := &grpc.StreamDesc{ClientStreams: true, ServerStreams: true}

	for name, method := range map[string]string{
		"input":  sentinelv1.SentinelService_ValidateInputStream_FullMethodName,
		"output": sentinelv1.SentinelService_ValidateOutputStream_FullMethodName,
	} {
		// Without a token the server must reject the stream.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		s, err := conn.NewStream(ctx, desc, method)
		if err == nil {
			_ = s.SendMsg(validProtoRequest("hello"))
			var resp sentinelv1.ValidateResponse
			err = s.RecvMsg(&resp)
		}
		wantCode(t, name+" stream without token", err, codes.Unauthenticated)
		cancel()

		// With a token the stream is accepted: closing it cleanly ends with EOF, not an auth error.
		ctx, cancel = context.WithTimeout(withBearer(context.Background(), "s3cret-token"), 5*time.Second)
		s, err = conn.NewStream(ctx, desc, method)
		if err != nil {
			t.Fatalf("%s stream with token: open: %v", name, err)
		}
		_ = s.CloseSend()
		var resp sentinelv1.ValidateResponse
		if err := s.RecvMsg(&resp); err != nil && err != io.EOF {
			if c := status.Code(err); c == codes.Unauthenticated {
				t.Errorf("%s stream with token was rejected: %v", name, err)
			}
		}
		cancel()
	}
}
