package mcp

import (
	"fmt"
	"net/url"
	"os"
	"strings"
)

type ClientCredLookup interface {
	Lookup(string) (string, string, error)
}

func NewClientLookupFromEnv() ClientCredLookup {
	return &envClientCredLookup{}
}

type envClientCredLookup struct{}

func (l *envClientCredLookup) Lookup(key string) (string, string, error) {
	u, err := url.Parse(key)
	if err != nil {
		return "", "", fmt.Errorf("failed to parse url: %w", err)
	}

	envBase := strings.ReplaceAll(strings.ReplaceAll(u.Host, ".", "_"), ":", "_")
	if u.Path != "" && u.Path != "/" {
		envBase += strings.ReplaceAll(strings.TrimSuffix(u.Path, "/"), "/", "_")
	}

	envBase = strings.ToUpper(strings.ReplaceAll(envBase, "-", "_"))
	return os.Getenv(envBase + "_CLIENT_ID"), os.Getenv(envBase + "_CLIENT_SECRET"), nil
}
