package main

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sivasreeonline/orbit-engine/services/execution-runner/internal/httpapi"
)

func main() {
	addr := os.Getenv("RUNNER_ADDR")
	if addr == "" {
		addr = "127.0.0.1:8080"
	}

	if err := requireLoopbackAddress(addr); err != nil {
		log.Fatalf("refusing to start runner: %v", err)
	}

	server := &http.Server{
		Addr:              addr,
		Handler:           httpapi.NewMux(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		<-ctx.Done()

		shutdownContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := server.Shutdown(shutdownContext); err != nil {
			log.Printf("runner shutdown did not complete cleanly: %v", err)
		}
	}()

	log.Printf("runner health process listening on %s; sandbox execution is disabled", addr)

	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("runner HTTP server failed: %v", err)
	}
}

func requireLoopbackAddress(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return errors.New("RUNNER_ADDR must be a valid host:port")
	}

	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("only loopback bind addresses are allowed until authenticated private transport is implemented")
	}

	return nil
}
