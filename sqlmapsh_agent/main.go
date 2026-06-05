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

const (
	defaultHooksPath  = "/opt/sqlmap-hooks"
	defaultSourcePath = "/opt/sqlmap-source"
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

func envListWithDefaults(name string, defaults ...string) string {
	seen := make(map[string]struct{})
	items := make([]string, 0, len(defaults)+1)

	for _, item := range defaults {
		trimmed := strings.TrimSpace(item)
		if trimmed == "" {
			continue
		}
		if _, exists := seen[trimmed]; exists {
			continue
		}
		seen[trimmed] = struct{}{}
		items = append(items, trimmed)
	}

	current := strings.TrimSpace(os.Getenv(name))
	if current != "" {
		for _, item := range strings.Split(current, ":") {
			trimmed := strings.TrimSpace(item)
			if trimmed == "" {
				continue
			}
			if _, exists := seen[trimmed]; exists {
				continue
			}
			seen[trimmed] = struct{}{}
			items = append(items, trimmed)
		}
	}

	return strings.Join(items, ":")
}

func buildCommandEnv() []string {
	envMap := make(map[string]string)

	for _, entry := range os.Environ() {
		parts := strings.SplitN(entry, "=", 2)
		key := parts[0]
		value := ""
		if len(parts) == 2 {
			value = parts[1]
		}
		envMap[key] = value
	}

	hooksPath := envOrDefault("SQLMAP_HOOKS_PATH", defaultHooksPath)
	sourcePath := envOrDefault("SQLMAP_SOURCE_PATH", defaultSourcePath)
	envMap["SQLMAP_HOOKS_PATH"] = hooksPath
	envMap["SQLMAP_SOURCE_PATH"] = sourcePath
	envMap["SQLMAP_REAL_PATH"] = envOrDefault("SQLMAP_REAL_PATH", sourcePath+"/sqlmap.py")
	envMap["SQLMAP_REAL_PYTHON"] = envOrDefault("SQLMAP_REAL_PYTHON", "python3")
	envMap["PYTHONPATH"] = envListWithDefaults("PYTHONPATH", hooksPath, sourcePath)

	result := make([]string, 0, len(envMap))
	for key, value := range envMap {
		result = append(result, fmt.Sprintf("%s=%s", key, value))
	}

	return result
}

func chooseDNSPort() string {
	current := strings.TrimSpace(os.Getenv("SQLMAP_DNS_PORT"))
	if current != "" && canBindUDPPort(current) {
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

func canBindUDPPort(port string) bool {
	parsed, err := strconv.Atoi(strings.TrimSpace(port))
	if err != nil || parsed <= 0 || parsed > 65535 {
		return false
	}
	conn, err := net.ListenPacket("udp4", net.JoinHostPort("", strconv.Itoa(parsed)))
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
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

func resolveRealSQLMapPath() string {
	candidates := []string{
		strings.TrimSpace(os.Getenv("SQLMAP_REAL_PATH")),
		"/opt/sqlmap-source/sqlmap.py",
		"/usr/local/share/sqlmap/sqlmap.py",
	}

	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate
		}
	}

	panic("unable to locate sqlmap.py; set SQLMAP_REAL_PATH explicitly")
}

func buildCommandArgs(interactURL string) []string {
	realSQLMap := resolveRealSQLMapPath()
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
	cmd.Env = buildCommandEnv()
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
