package main

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	interactshclient "github.com/projectdiscovery/interactsh/pkg/client"
	interactshserver "github.com/projectdiscovery/interactsh/pkg/server"
)

func envOrDefault(name string, defaultValue string) string {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return defaultValue
	}
	return value
}

func envInt(name string, defaultValue int) int {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return defaultValue
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return defaultValue
	}
	return parsed
}

func chooseDNSPort() string {
	current := strings.TrimSpace(os.Getenv("SQLMAP_DNS_PORT"))
	if current != "" {
		return current
	}

	start := envInt("SQLMAP_DNS_PORT_RANGE_START", 30000)
	end := envInt("SQLMAP_DNS_PORT_RANGE_END", 40000)
	if start > end {
		start, end = end, start
	}

	ports := rand.New(rand.NewSource(time.Now().UnixNano())).Perm(end - start + 1)
	for _, offset := range ports {
		port := start + offset
		conn, err := net.ListenPacket("udp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err == nil {
			_ = conn.Close()
			selected := strconv.Itoa(port)
			_ = os.Setenv("SQLMAP_DNS_PORT", selected)
			return selected
		}
	}

	panic(fmt.Sprintf("no available UDP port in range %d-%d", start, end))
}

func buildResolver() *net.Resolver {
	address := envOrDefault("SQLMAPSH_DNS_RESOLVER", "")
	if address == "" {
		port := chooseDNSPort()
		address = net.JoinHostPort("127.0.0.1", port)
	}

	proto := envOrDefault("SQLMAPSH_DNS_RESOLVER_PROTO", "udp")
	timeoutMs := 100
	if raw := strings.TrimSpace(os.Getenv("SQLMAPSH_DNS_TIMEOUT_MS")); raw != "" {
		fmt.Sscanf(raw, "%d", &timeoutMs)
		if timeoutMs <= 0 {
			timeoutMs = 100
		}
	}

	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network string, _ string) (net.Conn, error) {
			dialer := net.Dialer{
				Timeout: time.Duration(timeoutMs) * time.Millisecond,
			}
			return dialer.DialContext(ctx, proto, address)
		},
	}
}

func relayInteractions(ctx context.Context, resolver *net.Resolver, interaction *interactshserver.Interaction) {
	if interaction == nil || interaction.Protocol != "dns" {
		return
	}

	lookupCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	_, _ = resolver.LookupHost(lookupCtx, interaction.FullId)
}

func buildCommandArgs(interactURL string) []string {
	realSQLMap := envOrDefault("SQLMAP_REAL_PATH", "")
	if realSQLMap == "" {
		panic("SQLMAP_REAL_PATH is required")
	}

	args := []string{realSQLMap, "--dns-domain=" + interactURL}
	args = append(args, os.Args[1:]...)
	return args
}

func main() {
	pythonBin := envOrDefault("SQLMAP_REAL_PYTHON", "python3")
	resolver := buildResolver()

	client, err := interactshclient.New(interactshclient.DefaultOptions)
	if err != nil {
		panic(err)
	}
	defer client.Close()

	if err := client.StartPolling(500*time.Millisecond, func(interaction *interactshserver.Interaction) {
		relayInteractions(context.Background(), resolver, interaction)
	}); err != nil {
		panic(err)
	}
	defer client.StopPolling()

	cmd := exec.Command(pythonBin, buildCommandArgs(client.URL())...)
	cmd.Env = os.Environ()
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		panic(err)
	}

	signalCh := make(chan os.Signal, 4)
	signal.Notify(signalCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(signalCh)

	go func() {
		for sig := range signalCh {
			if cmd.Process != nil {
				_ = cmd.Process.Signal(sig)
			}
		}
	}()

	if err := cmd.Wait(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		panic(err)
	}
}
