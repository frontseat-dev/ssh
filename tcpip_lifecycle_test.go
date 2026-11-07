package ssh

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"
)

// Pausing the accept-error log exposes the legal ordering where a cancelled
// listener finishes its accept loop after another listener has reused its port.
// This leaves the production listener and synchronization code unchanged.
type acceptCleanupGate struct {
	slog.Handler
	once    sync.Once
	entered chan struct{}
	release chan struct{}
}

func (g *acceptCleanupGate) Handle(ctx context.Context, record slog.Record) error {
	if record.Message == "ssh: reverse port forward accept failed" {
		g.once.Do(func() {
			close(g.entered)
			<-g.release
		})
	}
	return nil
}

func TestReverseForwardOldCleanupKeepsReusedPort(t *testing.T) {
	gate := &acceptCleanupGate{
		Handler: slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug}),
		entered: make(chan struct{}), release: make(chan struct{}),
	}
	logger := slog.Default()
	slog.SetDefault(slog.New(gate))
	t.Cleanup(func() { slog.SetDefault(logger) })
	release := sync.OnceFunc(func() { close(gate.release) })
	t.Cleanup(release)
	h, ctx, srv, _ := reverseForwardFixture(t)
	first := requestReverseForward(t, h, ctx, srv, 0)
	address := first.Addr().String()
	_, portString, _ := net.SplitHostPort(address)
	port, _ := strconv.Atoi(portString)
	assertForwardBound(t, address)
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-gate.entered:
	case <-time.After(time.Second):
		t.Fatal("old listener did not reach cleanup")
	}
	second := requestReverseForward(t, h, ctx, srv, uint32(port))
	assertForwardBound(t, address)
	release()
	// Give the old accept loop a chance to finish while the replacement is
	// still active. Without the ownership check it deletes the replacement.
	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) {
		h.Lock()
		current := h.forwards[address]
		h.Unlock()
		if current != second {
			t.Fatal("old listener cleanup removed the replacement listener")
		}
		time.Sleep(time.Millisecond)
	}
	allowed, _ := h.HandleSSHRequest(ctx, srv, &gossh.Request{
		Type:    "cancel-tcpip-forward",
		Payload: gossh.Marshal(&remoteForwardCancelRequest{BindAddr: "127.0.0.1", BindPort: uint32(port)}),
	})
	if !allowed {
		t.Fatal("replacement cancellation was refused")
	}
	assertForwardReleased(t, address)
}

func TestReverseForwardDisconnectClosesItsCapturedListener(t *testing.T) {
	h, ctx, srv, cancel := reverseForwardFixture(t)
	listener := requestReverseForward(t, h, ctx, srv, 0)
	address := listener.Addr().String()
	assertForwardBound(t, address)
	// Cleanup must not depend on an address still having a registry entry.
	h.Lock()
	delete(h.forwards, address)
	h.Unlock()
	cancel()
	assertForwardReleased(t, address)
}

func reverseForwardFixture(t *testing.T) (*ForwardedTCPHandler, Context, *Server, context.CancelFunc) {
	t.Helper()
	srv := &Server{ReversePortForwardingCallback: func(Context, string, uint32) bool { return true }}
	ctx, cancel := newContext(srv)
	t.Cleanup(cancel)
	ctx.SetValue(ContextKeyConn, (*gossh.ServerConn)(nil))
	return &ForwardedTCPHandler{}, ctx, srv, cancel
}

func requestReverseForward(t *testing.T, h *ForwardedTCPHandler, ctx Context, srv *Server, port uint32) net.Listener {
	t.Helper()
	allowed, payload := h.HandleSSHRequest(ctx, srv, &gossh.Request{
		Type:    "tcpip-forward",
		Payload: gossh.Marshal(&remoteForwardRequest{BindAddr: "127.0.0.1", BindPort: port}),
	})
	if !allowed {
		t.Fatal("reverse forwarding was refused")
	}
	var response remoteForwardSuccess
	if err := gossh.Unmarshal(payload, &response); err != nil {
		t.Fatal(err)
	}
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(response.BindPort)))
	h.Lock()
	listener := h.forwards[address]
	h.Unlock()
	if listener == nil {
		t.Fatal("forwarded listener is absent")
	}
	t.Cleanup(func() { _ = listener.Close() })
	return listener
}

func assertForwardBound(t *testing.T, address string) {
	t.Helper()
	listener, err := net.Listen("tcp", address)
	if listener != nil {
		_ = listener.Close()
	}
	if !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("forward does not own its port: %v", err)
	}
}

func assertForwardReleased(t *testing.T, address string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		listener, err := net.Listen("tcp", address)
		if err == nil {
			_ = listener.Close()
			return
		}
		if !errors.Is(err, syscall.EADDRINUSE) || time.Now().After(deadline) {
			t.Fatalf("forwarded port was not released: %v", err)
		}
		time.Sleep(time.Millisecond)
	}
}
