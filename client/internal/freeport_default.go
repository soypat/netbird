//go:build !js

package internal

import (
	"errors"
	"fmt"
	"net"
	"time"

	log "github.com/sirupsen/logrus"
)

// freePort attempts to determine if the provided port is available, if not it will ask the system for a free port.
func freePort(initPort int) (int, error) {
	addr := net.UDPAddr{Port: initPort}

	conn, err := net.ListenUDP("udp", &addr)
	if err == nil {
		returnPort := conn.LocalAddr().(*net.UDPAddr).Port
		closeConnWithLog(conn)
		return returnPort, nil
	}

	// if the port is already in use, ask the system for a free port
	addr.Port = 0
	conn, err = net.ListenUDP("udp", &addr)
	if err != nil {
		return 0, fmt.Errorf("unable to get a free port: %v", err)
	}

	udpAddr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return 0, errors.New("wrong address type when getting a free port")
	}
	closeConnWithLog(conn)
	return udpAddr.Port, nil
}

func closeConnWithLog(conn *net.UDPConn) {
	startClosing := time.Now()
	err := conn.Close()
	if err != nil {
		log.Warnf("closing probe port %d failed: %v. NetBird will still attempt to use this port for connection.", conn.LocalAddr().(*net.UDPAddr).Port, err)
	}
	if time.Since(startClosing) > time.Second {
		log.Warnf("closing the testing port %d took %s. Usually it is safe to ignore, but continuous warnings may indicate a problem.", conn.LocalAddr().(*net.UDPAddr).Port, time.Since(startClosing))
	}
}
