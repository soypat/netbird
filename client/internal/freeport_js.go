//go:build js

package internal

// freePort cannot probe OS UDP sockets in the browser. Under js/wasm the
// WireGuard endpoint is provided by the in-memory/netstack path, so keep the
// configured port and avoid calling net.ListenUDP before a TinyGo netdev exists.
func freePort(initPort int) (int, error) {
	return initPort, nil
}
