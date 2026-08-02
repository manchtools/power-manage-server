package main

import (
	"net"
	"net/http"
	"testing"
	"time"

	proxyproto "github.com/pires/go-proxyproto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHTTPServerReadTimeouts(t *testing.T) {
	t.Parallel()

	public, err := buildPublicServer(&Config{PublicListen: "127.0.0.1:0"}, http.NotFoundHandler())
	require.NoError(t, err)
	assert.Equal(t, publicRequestReadTimeout, public.ReadTimeout,
		"the public listener must bound slow request bodies")
}

func TestAgentProxyListenerRequiresTrustedProxyHeader(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	proxyListener, err := agentProxyListener(listener, []string{"127.0.0.1"})
	require.NoError(t, err)

	accepted := make(chan net.Conn, 1)
	acceptErrors := make(chan error, 1)
	go func() {
		connection, acceptErr := proxyListener.Accept()
		if acceptErr != nil {
			acceptErrors <- acceptErr
			return
		}
		accepted <- connection
	}()

	proxyConnection, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = proxyConnection.Close() })
	clientAddress := &net.TCPAddr{IP: net.ParseIP("192.0.2.42"), Port: 4242}
	header := proxyproto.HeaderProxyFromAddrs(2, clientAddress, listener.Addr())
	_, err = header.WriteTo(proxyConnection)
	require.NoError(t, err)

	select {
	case connection := <-accepted:
		t.Cleanup(func() { _ = connection.Close() })
		assert.Equal(t, clientAddress.String(), connection.RemoteAddr().String())
	case err := <-acceptErrors:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for PROXY-v2 connection")
	}
}

func TestAgentProxyListenerRejectsInvalidTraffic(t *testing.T) {
	tests := map[string]struct {
		write       func(*testing.T, net.Conn, net.Addr)
		expectedErr error
	}{
		"headerless": {
			write: func(t *testing.T, connection net.Conn, _ net.Addr) {
				_, err := connection.Write([]byte("not a proxy header"))
				require.NoError(t, err)
			},
			expectedErr: proxyproto.ErrNoProxyProtocol,
		},
		"version one": {
			write: func(t *testing.T, connection net.Conn, destination net.Addr) {
				header := proxyproto.HeaderProxyFromAddrs(1, connection.LocalAddr(), destination)
				_, err := header.WriteTo(connection)
				require.NoError(t, err)
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			t.Cleanup(func() { _ = listener.Close() })

			proxyListener, err := agentProxyListener(listener, []string{"127.0.0.1"})
			require.NoError(t, err)

			readErrors := make(chan error, 1)
			go func() {
				connection, acceptErr := proxyListener.Accept()
				if acceptErr != nil {
					readErrors <- acceptErr
					return
				}
				defer func() { _ = connection.Close() }()
				_, readErr := connection.Read(make([]byte, 1))
				readErrors <- readErr
			}()

			connection, err := net.Dial("tcp", listener.Addr().String())
			require.NoError(t, err)
			test.write(t, connection, listener.Addr())
			require.NoError(t, connection.Close())

			select {
			case err := <-readErrors:
				if test.expectedErr == nil {
					assert.Error(t, err)
				} else {
					assert.ErrorIs(t, err, test.expectedErr)
				}
			case <-time.After(time.Second):
				t.Fatal("timed out waiting for invalid connection rejection")
			}
		})
	}
}
