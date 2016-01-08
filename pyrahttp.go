package pyrahttp

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"
)

// https://golang.org/src/net/http/server.go?s=59426:59517#L1988
func ListenAndServeLetsEncrypt(addr string, certFile string, keyFile string, handler http.Handler) error {

	for {

		srv := &http.Server{Addr: addr, Handler: handler}

		if addr == "" {
			addr = ":https"
		}
		config := cloneTLSConfig(srv.TLSConfig)
		if config.NextProtos == nil {
			config.NextProtos = []string{"http/1.1"}
		}

		if len(config.Certificates) == 0 || certFile != "" || keyFile != "" {
			var err error
			config.Certificates = make([]tls.Certificate, 1)
			config.Certificates[0], err = tls.LoadX509KeyPair(certFile, keyFile)
			if err != nil {
				return err
			}
		}

		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return err
		}

		// tlsListener := tls.NewListener(tcpKeepAliveListener{ln.(*net.TCPListener)}, config)
		tlsListener := tls.NewListener(tcpKeepAliveListener{ln.(*net.TCPListener)}, config)

		sl, err := New(tlsListener, certFile, keyFile)
		if err != nil {
			return err
		}
		err = srv.Serve(sl)

		if err == ReloadError {
			fmt.Printf("Reloading certs %s %s\n", keyFile, certFile)
			continue
		}

		return err
	}

}

// taken from https://golang.org/src/net/http/transport.go#L1396

// cloneTLSConfig returns a shallow clone of the exported
// fields of cfg, ignoring the unexported sync.Once, which
// contains a mutex and must not be copied.
//
// The cfg must not be in active use by tls.Server, or else
// there can still be a race with tls.Server updating SessionTicketKey
// and our copying it, and also a race with the server setting
// SessionTicketsDisabled=false on failure to set the random
// ticket key.
//
// If cfg is nil, a new zero tls.Config is returned.
func cloneTLSConfig(cfg *tls.Config) *tls.Config {
	if cfg == nil {
		return &tls.Config{}
	}
	return &tls.Config{
		Rand:                     cfg.Rand,
		Time:                     cfg.Time,
		Certificates:             cfg.Certificates,
		NameToCertificate:        cfg.NameToCertificate,
		GetCertificate:           cfg.GetCertificate,
		RootCAs:                  cfg.RootCAs,
		NextProtos:               cfg.NextProtos,
		ServerName:               cfg.ServerName,
		ClientAuth:               cfg.ClientAuth,
		ClientCAs:                cfg.ClientCAs,
		InsecureSkipVerify:       cfg.InsecureSkipVerify,
		CipherSuites:             cfg.CipherSuites,
		PreferServerCipherSuites: cfg.PreferServerCipherSuites,
		SessionTicketsDisabled:   cfg.SessionTicketsDisabled,
		SessionTicketKey:         cfg.SessionTicketKey,
		ClientSessionCache:       cfg.ClientSessionCache,
		MinVersion:               cfg.MinVersion,
		MaxVersion:               cfg.MaxVersion,
		CurvePreferences:         cfg.CurvePreferences,
	}
}

// https://github.com/hydrogen18/stoppableListener/blob/master/listener.go
type StoppableListener struct {
	*net.TCPListener //Wrapped listener
	certFile         string
	keyFile          string
	certTime         int64
	keyTime          int64
}

func New(l net.Listener, certFile string, keyFile string) (*StoppableListener, error) {
	tcpL, ok := l.(*net.TCPListener)

	if !ok {
		return nil, errors.New("Cannot wrap listener")
	}

	retval := &StoppableListener{}
	retval.TCPListener = tcpL
	retval.certFile = certFile
	fi, err := os.Stat(certFile)
	if err != nil {
		return nil, err
	}
	retval.certTime = fi.ModTime().UnixNano()
	retval.keyFile = keyFile
	fi, err = os.Stat(keyFile)
	if err != nil {
		return nil, err
	}
	retval.keyTime = fi.ModTime().UnixNano()

	return retval, nil
}

var ReloadError = errors.New("Listener stopped")

func (sl *StoppableListener) Accept() (net.Conn, error) {

	for {
		//Wait up to one second for a new connection
		sl.SetDeadline(time.Now().Add(time.Minute))

		newConn, err := sl.TCPListener.AcceptTCP()

		newConn.SetKeepAlive(true)
		newConn.SetKeepAlivePeriod(3 * time.Minute)

		fi, err1 := os.Stat(sl.certFile)
		if err1 == nil {
			if fi.ModTime().UnixNano() != sl.certTime {
				return nil, ReloadError
			}
		}

		fi, err1 = os.Stat(sl.keyFile)
		if err1 == nil {
			if fi.ModTime().UnixNano() != sl.keyTime {
				return nil, ReloadError
			}
		}

		if err != nil {
			netErr, ok := err.(net.Error)

			//If this is a timeout, then continue to wait for
			//new connections
			if ok && netErr.Timeout() && netErr.Temporary() {
				continue
			}
		}

		return newConn, err
	}
}

// tcpKeepAliveListener sets TCP keep-alive timeouts on accepted
// connections. It's used by ListenAndServe and ListenAndServeTLS so
// dead TCP connections (e.g. closing laptop mid-download) eventually
// go away.
type tcpKeepAliveListener struct {
	*net.TCPListener
}

func (ln tcpKeepAliveListener) Accept() (c net.Conn, err error) {
	tc, err := ln.AcceptTCP()
	if err != nil {
		return
	}
	tc.SetKeepAlive(true)
	tc.SetKeepAlivePeriod(3 * time.Minute)
	return tc, nil
}
