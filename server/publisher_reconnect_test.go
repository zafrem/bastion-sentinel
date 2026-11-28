package server

import (
	"bufio"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeBus speaks just enough of the NATS protocol to accept a publisher and record what it sends.
type fakeBus struct {
	t    *testing.T
	addr string

	mu       sync.Mutex
	lis      net.Listener
	conns    []net.Conn
	subjects []string
}

func newFakeBus(t *testing.T) *fakeBus {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := lis.Addr().String()
	_ = lis.Close() // reserved for later: the server starts out down
	b := &fakeBus{t: t, addr: addr}
	t.Cleanup(b.stop)
	return b
}

func (b *fakeBus) start() {
	lis, err := net.Listen("tcp", b.addr)
	if err != nil {
		b.t.Fatal(err)
	}
	b.mu.Lock()
	b.lis = lis
	b.mu.Unlock()
	go func() {
		for {
			conn, err := lis.Accept()
			if err != nil {
				return
			}
			b.mu.Lock()
			b.conns = append(b.conns, conn)
			b.mu.Unlock()
			go b.serve(conn)
		}
	}()
}

func (b *fakeBus) serve(conn net.Conn) {
	_, _ = io.WriteString(conn, "INFO {\"server_id\":\"fake\",\"version\":\"2.10.0\",\"proto\":1,\"max_payload\":1048576}\r\n")
	r := bufio.NewReader(conn)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		fields := strings.Fields(line)
		switch {
		case len(fields) == 0:
		case fields[0] == "PING":
			_, _ = io.WriteString(conn, "PONG\r\n")
		case fields[0] == "PUB":
			n, err := strconv.Atoi(fields[len(fields)-1])
			if err != nil {
				return
			}
			if _, err := io.CopyN(io.Discard, r, int64(n)+2); err != nil {
				return
			}
			b.mu.Lock()
			b.subjects = append(b.subjects, fields[1])
			b.mu.Unlock()
		}
	}
}

func (b *fakeBus) stop() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.lis != nil {
		_ = b.lis.Close()
	}
	for _, c := range b.conns {
		_ = c.Close()
	}
	b.lis, b.conns = nil, nil
}

func (b *fakeBus) received(subject string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, s := range b.subjects {
		if s == subject {
			return true
		}
	}
	return false
}

// delivers publishes events of the given type until one arrives.
func delivers(t *testing.T, b *fakeBus, publish func(eventType string), eventType, when string) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		publish(eventType)
		if b.received(subjectPrefix + "." + eventType) {
			return
		}
	}
	t.Fatalf("no event arrived %s", when)
}

// An outage much longer than a handful of retries must not silence the module until it is restarted.
func TestPublisher_SurvivesNATSBeingAway(t *testing.T) {
	old := reconnectWait
	reconnectWait = 20 * time.Millisecond
	defer func() { reconnectWait = old }()

	bus := newFakeBus(t)
	p := NewEventPublisher("nats://" + bus.addr) // NATS is not up yet
	defer p.Close()
	publish := func(eventType string) { p.Publish(SentinelEvent{EventType: eventType}) }

	time.Sleep(1500 * time.Millisecond)
	bus.start()
	delivers(t, bus, publish, "after_late_start", "after NATS started late")

	bus.stop()
	time.Sleep(1500 * time.Millisecond)
	bus.start()
	delivers(t, bus, publish, "after_outage", "after an outage")
}
