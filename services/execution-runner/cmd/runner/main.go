package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sivasreeonline/orbit-engine/services/execution-runner/internal/acceptancejournal"
	"github.com/sivasreeonline/orbit-engine/services/execution-runner/internal/httpapi"
	"github.com/sivasreeonline/orbit-engine/services/execution-runner/internal/runner"
	"github.com/sivasreeonline/orbit-engine/services/execution-runner/internal/runnerclient"
	"github.com/sivasreeonline/orbit-engine/services/execution-runner/internal/runnerconfig"
)

func main() {
	if err := run(); err != nil {
		log.Printf("runner stopped with error: %v", err)
		os.Exit(1)
	}
}

func run() error {
	addr := os.Getenv("RUNNER_ADDR")
	if addr == "" {
		addr = "127.0.0.1:8080"
	}
	if err := requireLoopbackAddress(addr); err != nil {
		return fmt.Errorf("refusing to start runner: %w", err)
	}

	mode := os.Getenv("RUNNER_MODE")
	if mode == "" {
		mode = "health"
	}
	if mode != "health" && mode != "foreground" {
		return errors.New("RUNNER_MODE must be either health or foreground")
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

	if mode == "foreground" {
		return runForeground(ctx, server)
	}
	return runHealth(ctx, server, addr)
}

func runHealth(ctx context.Context, server *http.Server, addr string) error {
	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		<-ctx.Done()
		shutdownContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownContext); err != nil {
			log.Printf("runner HTTP shutdown did not complete cleanly: %v", err)
		}
	}()

	log.Printf("runner health process listening on %s; sandbox execution is disabled", addr)
	err := server.ListenAndServe()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("runner HTTP server failed: %w", err)
	}
	if ctx.Err() != nil {
		<-shutdownDone
	}
	return nil
}

// runForeground validates and opens the authenticated runner identity resources,
// but deliberately installs a permanently closed qualification gate. This
// exercises process ownership and shutdown without claiming student work.
func runForeground(ctx context.Context, server *http.Server) (returnErr error) {
	config, err := runnerconfig.Load(os.LookupEnv)
	if err != nil {
		return fmt.Errorf("load foreground runner identity: %w", err)
	}
	defer config.Destroy()

	client, err := runnerclient.New(runnerclient.Config{
		ControlPlaneURL: config.ControlPlaneURL,
		KeyID:           config.KeyID,
		PrivateKey:      config.PrivateKey,
	})
	if err != nil {
		return fmt.Errorf("initialize authenticated runner client: %w", err)
	}

	// The client owns a private copy, so clear the loader's copy immediately.
	config.Destroy()
	defer func() {
		if err := client.Close(); err != nil {
			returnErr = errors.Join(returnErr, err)
		}
	}()

	journal, err := acceptancejournal.Open(config.JournalPath)
	if err != nil {
		return fmt.Errorf("open durable acceptance journal: %w", err)
	}
	defer func() {
		if err := journal.Close(); err != nil {
			returnErr = errors.Join(returnErr, err)
		}
	}()

	worker, err := runner.NewWorker(client, journal, runner.UnconfiguredArtifactExecutor{}, runner.WorkerConfig{})
	if err != nil {
		return fmt.Errorf("initialize foreground worker: %w", err)
	}
	supervisor, err := runner.NewSupervisor(worker, runner.DisabledQualificationGate{}, runner.SupervisorConfig{})
	if err != nil {
		return fmt.Errorf("initialize foreground supervisor: %w", err)
	}

	workerContext, cancelWorker := context.WithCancel(ctx)
	workerDone := make(chan error, 1)
	go func() {
		workerDone <- supervisor.Run(workerContext)
	}()

	serverDone := make(chan error, 1)
	go func() {
		serverDone <- server.ListenAndServe()
	}()

	log.Printf("runner foreground process listening on %s; identity and journal initialized; qualification gate is CLOSED and dispatch claims are disabled", server.Addr)

	select {
	case <-ctx.Done():
		cancelWorker()
		workerErr := <-workerDone
		shutdownContext, cancelShutdown := context.WithTimeout(context.Background(), 5*time.Second)
		shutdownErr := server.Shutdown(shutdownContext)
		cancelShutdown()
		serverErr := <-serverDone
		if workerErr != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("stop foreground supervisor: %w", workerErr))
		}
		if shutdownErr != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("shutdown runner HTTP server: %w", shutdownErr))
		}
		if serverErr != nil && !errors.Is(serverErr, http.ErrServerClosed) {
			returnErr = errors.Join(returnErr, fmt.Errorf("runner HTTP server failed during shutdown: %w", serverErr))
		}
		return returnErr
	case err := <-serverDone:
		cancelWorker()
		workerErr := <-workerDone
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			returnErr = errors.Join(returnErr, fmt.Errorf("runner HTTP server failed: %w", err))
		}
		if workerErr != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("stop foreground supervisor: %w", workerErr))
		}
		return returnErr
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
