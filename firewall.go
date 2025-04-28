package firewall

import (
	"net"
	"net/http"

	"github.com/BurntSushi/toml"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func init() {
	caddy.RegisterModule(Firewall{})
}

type Firewall struct {
	Allow []string `json:"allow,omitempty"`
	Block []string `json:"block,omitempty"`
}

func (Firewall) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.firewall",
		New: func() caddy.Module { return new(Firewall) },
	}
}

func (m *Firewall) Provision(ctx caddy.Context) error {
	// carrega o arquivo firewall.toml
	var conf struct {
		Allow []string `toml:"allow"`
		Block []string `toml:"block"`
	}
	if _, err := toml.DecodeFile("/etc/caddy/firewall.toml", &conf); err != nil {
		return err
	}
	m.Allow = conf.Allow
	m.Block = conf.Block
	return nil
}

func (m Firewall) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	clientIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return err
	}

	// Bloqueio prioritário
	for _, blocked := range m.Block {
		if blocked == clientIP {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return nil
		}
	}

	// Liberação se listado
	if len(m.Allow) > 0 {
		allowed := false
		for _, allowedIP := range m.Allow {
			if allowedIP == clientIP {
				allowed = true
				break
			}
		}
		if !allowed {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return nil
		}
	}

	// Se não está bloqueado, e não tem allow list, passa
	return next.ServeHTTP(w, r)
}

// Para suporte a Caddyfile (opcional)
func (m *Firewall) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	return nil
}