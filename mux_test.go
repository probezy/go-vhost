package vhost

import (
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestErrors ensures that error types for this package are implemented properly
func TestErrors(t *testing.T) {
	// test case for https://github.com/inconshreveable/go-vhost/pull/2
	// create local err vars of error interface type
	var notFoundErr error
	var badRequestErr error
	var closedErr error

	// stuff local error types in to interface values
	notFoundErr = NotFound{fmt.Errorf("test NotFound")}
	badRequestErr = BadRequest{fmt.Errorf("test BadRequest")}
	closedErr = Closed{fmt.Errorf("test Closed")}

	// assert the types
	switch errType := notFoundErr.(type) {
	case NotFound:
	default:
		t.Fatalf("expected NotFound, got: %s", errType)
	}
	switch errType := badRequestErr.(type) {
	case BadRequest:
	default:
		t.Fatalf("expected BadRequest, got: %s", errType)
	}
	switch errType := closedErr.(type) {
	case Closed:
	default:
		t.Fatalf("expected Closed, got: %s", errType)
	}
}

func localListener(t *testing.T) (net.Listener, string) {
	l, err := net.Listen("tcp", "192.168.9.50:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	return l, strconv.Itoa(l.Addr().(*net.TCPAddr).Port)
}

func TestHTTPMux(t *testing.T) {
	l, port := localListener(t)
	mux, err := NewHTTPMuxer(l, time.Second)
	if err != nil {
		t.Fatalf("failed to start muxer: %v", err)
	}
	// go mux.HandleErrors()

	go func() {
		go mux.HandleErrors()

		for {
			conn, err := mux.NextError()

			switch err.(type) {
			case BadRequest:
				t.Errorf("got a bad request!")
				conn.Write([]byte("bad request"))
			case NotFound:
				var vhostConn *TLSConn
				if vhostConn, err = TLS(conn); err != nil {
					// panic("Not a valid TLS connection!")
					t.Errorf("Not a valid TLS connection!")
					conn.Write([]byte("Not a valid TLS connection!"))
				}
				t.Errorf("got a connection for an unknown vhost: %s", vhostConn.Host())
				conn.Write([]byte("vhost not found"))
			case Closed:
				t.Errorf("closed conn: %s", err)
			default:
				if conn != nil {
					conn.Write([]byte("server error"))
				}
			}

			if conn != nil {
				conn.Close()
			}
		}
	}()

	muxed, err := mux.Listen("example.com")
	if err != nil {
		t.Fatalf("failed to listen on muxer: %v", muxed)
	}

	go http.Serve(muxed, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(w, r.Body)
	}))

	msg := "test"
	url := "https://aaa.cpolar.io:" + port
	//resp, err := http.Post(url, "text/plain", strings.NewReader(msg))
	//if err != nil {
	//	t.Fatalf("failed to post: %v", err)
	//}
	//
	//if resp.StatusCode != 404 {
	//	t.Fatalf("sent incorrect host header, expected 404 but got %d", resp.StatusCode)
	//}

	req, err := http.NewRequest("POST", url, strings.NewReader(msg))
	if err != nil {
		t.Fatalf("failed to construct HTTP request: %v", err)
	}
	req.Host = "aaa.cpolar.io"
	req.Header.Set("Content-Type", "text/plain")

	resp, err := new(http.Client).Do(req)
	if err != nil {
		t.Fatalf("failed to make HTTP request: %v", err)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read: %v", err)
	}

	got := string(body)
	if got != msg {
		t.Fatalf("unexpected resposne. got: %v, expected: %v", got, msg)
	}
}

func TestHTTPMuxNew(t *testing.T) {
	l, port := localListener(t)
	mux, err := NewHTTPMuxer(l, time.Second)
	if err != nil {
		t.Fatalf("failed to start muxer: %v", err)
	}
	go mux.HandleErrors()

	var lazyLoading LazyLoadingFn = func(name string) (muxer net.Listener, ok bool) {

		if name == "example.com" {
			muxer, err := mux.Listen("example.com")
			if err != nil {
				t.Fatalf("failed to listen on muxer: %v", muxer)
			}

			go http.Serve(muxer, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				io.Copy(w, r.Body)
			}))
			return muxer, true
		}
		return nil, false
	}

	mux.VhostLazyLoader = lazyLoading

	msg := "test"
	url := "http://localhost:" + port
	resp, err := http.Post(url, "text/plain", strings.NewReader(msg))
	if err != nil {
		t.Fatalf("failed to post: %v", err)
	}

	if resp.StatusCode != 404 {
		t.Fatalf("sent incorrect host header, expected 404 but got %d", resp.StatusCode)
	}

	req, err := http.NewRequest("POST", url, strings.NewReader(msg))
	if err != nil {
		t.Fatalf("failed to construct HTTP request: %v", err)
	}
	req.Host = "example.com"
	req.Header.Set("Content-Type", "text/plain")

	resp, err = new(http.Client).Do(req)
	if err != nil {
		t.Fatalf("failed to make HTTP request: %v", err)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read: %v", err)
	}

	got := string(body)
	if got != msg {
		t.Fatalf("unexpected resposne. got: %v, expected: %v", got, msg)
	}
}

func TestHTTPSMuxNewLazyLoading(t *testing.T) {
	l, port := localListener(t)
	mux, err := NewTLSMuxer(l, time.Second*90)
	if err != nil {
		t.Fatalf("failed to start muxer: %v", err)
	}
	go func() {
		go mux.HandleErrors()

		for {
			conn, err := mux.NextError()

			switch err.(type) {
			case BadRequest:
				t.Errorf("got a bad request!")
				conn.Write([]byte("bad request"))
			case NotFound:
				var vhostConn *TLSConn
				if vhostConn, err = TLS(conn); err != nil {
					// panic("Not a valid TLS connection!")
					t.Errorf("Not a valid TLS connection!")
					conn.Write([]byte("Not a valid TLS connection!"))
				}
				t.Errorf("got a connection for an unknown vhost: %s", vhostConn.Host())
				conn.Write([]byte("vhost not found"))
			case Closed:
				t.Errorf("closed conn: %s", err)
			default:
				if conn != nil {
					conn.Write([]byte("server error"))
				}
			}

			if conn != nil {
				conn.Close()
			}
		}
	}()

	var lazyLoading LazyLoadingFn = func(name string) (muxer net.Listener, ok bool) {

		if name == "aaa.cpolar.io" {

			httpHandle := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				io.Copy(w, r.Body)
			})

			crt, err := buildTlsCrtFromFile("/Users/michael/.acme.sh/cpolar.io_ecc/fullchain.cer")
			key, err := buildTlsCrtFromFile("/Users/michael/.acme.sh/cpolar.io_ecc/cpolar.io.key")
			config, err := addCert(t, crt, key)

			server := &http.Server{
				Handler:   httpHandle,
				TLSConfig: config,
			}

			muxer, err := mux.Listen("aaa.cpolar.io")

			if err != nil {
				t.Fatalf("failed to listen on muxer: %v", muxer)
			}

			//go http.Serve(muxer,))
			go server.ServeTLS(muxer, "", "")

			return muxer, true
		}

		return nil, false
	}

	mux.VhostLazyLoader = lazyLoading

	msg := "test"
	url := "https://aaa.cpolar.io:" + port
	//resp, err := http.Post(url, "text/plain", strings.NewReader(msg))
	//if err != nil {
	//	t.Fatalf("failed to post: %v", err)
	//}
	//
	//if resp.StatusCode != 404 {
	//	t.Fatalf("sent incorrect host header, expected 404 but got %d", resp.StatusCode)
	//}

	req, err := http.NewRequest("POST", url, strings.NewReader(msg))
	if err != nil {
		t.Fatalf("failed to construct HTTP request: %v", err)
	}
	req.Host = "aaa.cpolar.io"
	req.Header.Set("Content-Type", "text/plain")

	resp, err := new(http.Client).Do(req)
	if err != nil {
		t.Fatalf("failed to make HTTP request: %v", err)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read: %v", err)
	}

	got := string(body)
	if got != msg {
		t.Fatalf("unexpected resposne. got: %v, expected: %v", got, msg)
	}
}

func TestHTTPSMuxNew(t *testing.T) {
	l, port := localListener(t)
	mux, err := NewTLSMuxer(l, time.Second*90)
	if err != nil {
		t.Fatalf("failed to start muxer: %v", err)
	}
	go func() {
		go mux.HandleErrors()

		for {
			conn, err := mux.NextError()

			switch err.(type) {
			case BadRequest:
				t.Errorf("got a bad request!")
				conn.Write([]byte("bad request"))
			case NotFound:
				var vhostConn *TLSConn
				if vhostConn, err = TLS(conn); err != nil {
					// panic("Not a valid TLS connection!")
					t.Errorf("Not a valid TLS connection!")
					conn.Write([]byte("Not a valid TLS connection!"))
				}
				t.Errorf("got a connection for an unknown vhost: %s", vhostConn.Host())
				conn.Write([]byte("vhost not found"))
			case Closed:
				t.Errorf("closed conn: %s", err)
			default:
				if conn != nil {
					conn.Write([]byte("server error"))
				}
			}

			if conn != nil {
				conn.Close()
			}
		}
	}()

	httpHandle := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(w, r.Body)
	})

	//crt, err := buildTlsCrtFromFile("/Users/michael/.acme.sh/cpolar.io_ecc/fullchain.cer")
	//key, err := buildTlsCrtFromFile("/Users/michael/.acme.sh/cpolar.io_ecc/cpolar.io.key")
	//config, err := addCert(t, crt, key)

	// 加载SSL证书
	certificate, err := tls.LoadX509KeyPair("/Users/michael/.acme.sh/cpolar.io_ecc/fullchain.cer", "/Users/michael/.acme.sh/cpolar.io_ecc/cpolar.io.key")
	if err != nil {
		log.Fatal(err)
	}

	// 创建TLS配置
	config := &tls.Config{
		Certificates: []tls.Certificate{certificate},
	}

	server := &http.Server{
		Handler:   httpHandle,
		TLSConfig: config,
	}

	muxer, err := mux.Listen("aaa.cpolar.io")

	if err != nil {
		t.Fatalf("failed to listen on muxer: %v", muxer)
	}

	//go http.Serve(muxer,))
	go server.ServeTLS(muxer, "", "")

	msg := "test"
	url := "https://aaa.cpolar.io:" + port
	//resp, err := http.Post(url, "text/plain", strings.NewReader(msg))
	//if err != nil {
	//	t.Fatalf("failed to post: %v", err)
	//}
	//
	//if resp.StatusCode != 404 {
	//	t.Fatalf("sent incorrect host header, expected 404 but got %d", resp.StatusCode)
	//}

	req, err := http.NewRequest("POST", url, strings.NewReader(msg))
	if err != nil {
		t.Fatalf("failed to construct HTTP request: %v", err)
	}
	req.Host = "aaa.cpolar.io"
	req.Header.Set("Content-Type", "text/plain")

	resp, err := new(http.Client).Do(req)
	if err != nil {
		t.Fatalf("failed to make HTTP request: %v", err)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read: %v", err)
	}

	got := string(body)
	if got != msg {
		t.Fatalf("unexpected resposne. got: %v, expected: %v", got, msg)
	}
}

func addCert(t *testing.T, cert []byte, key []byte) (tlsCfg *tls.Config, err error) {

	certAndKey, err := tls.X509KeyPair(cert, key)

	if err != nil {
		t.Error("tls.X509KeyPair error", err)
		return nil, err
	}
	tlsCfg = &tls.Config{
		Certificates: []tls.Certificate{certAndKey},
	}
	return tlsCfg, nil
}

//func createHttpsListener(hostName string, tlsConfig *tls.Config) (listener net.Listener, err error) {
//	//创建一个https Listener
//	//&reverseProxyHandle{remotePort: remotePort, photo: "https"}
//
//	httpHandle := server.NewReverseProxyHandle("https", htl.locationRegistry, htl.iPWhiteList)
//
//	//certBytes, err := ioutil.ReadFile("client.pem")
//	//if err != nil {
//	//	panic("Unable to read cert.pem")
//	//}
//	//clientCertPool := x509.NewCertPool()
//	//ok := clientCertPool.AppendCertsFromPEM(certBytes)
//	//if !ok {
//	//	panic("failed to parse root certificate")
//	//}
//
//	config := &tls.Config{
//		Certificates: tlsConfig.Certificates,
//		ClientAuth:   tlsConfig.ClientAuth,
//		ClientCAs:    tlsConfig.ClientCAs,
//	}
//
//	server := &http.Server{
//		Handler:   httpHandle,
//		TLSConfig: config,
//	}
//
//	listener, err = htl.tlsMux.Listen(hostName)
//	if err != nil {
//		log.Errorf("failed to listen on muxer: %v", listener)
//		return
//	}
//	htl.listener = listener
//
//	//需要创建一个全局的TlsListeners，可以通过TunnelId，默认为*.cpolar.io及它的证书
//	go htl.listenHTTPS(server, listener)
//
//	return listener, nil
//
//}

func listenHTTPS(t *testing.T, server *http.Server, listener net.Listener) {

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("HttpsTunnelListener listenTcp failed with error %v", r)
		}
	}()

	//TODO 这里最好加一个上下文的取消对象，这样可以完好的退出。

	server.ServeTLS(listener, "", "")

}

func TestTLSMuxNew(t *testing.T) {
	l, port := localListener(t)
	mux, err := NewTLSMuxer(l, time.Second*90)
	if err != nil {
		t.Fatalf("failed to start muxer: %v", err)
	}
	go func() {
		go mux.HandleErrors()

		for {
			conn, err := mux.NextError()

			switch err.(type) {
			case BadRequest:
				t.Errorf("got a bad request!")
				conn.Write([]byte("bad request"))
			case NotFound:
				var vhostConn *TLSConn
				if vhostConn, err = TLS(conn); err != nil {
					// panic("Not a valid TLS connection!")
					t.Errorf("Not a valid TLS connection!")
					conn.Write([]byte("Not a valid TLS connection!"))
				}
				t.Errorf("got a connection for an unknown vhost: %s", vhostConn.Host())
				conn.Write([]byte("vhost not found"))
			case Closed:
				t.Errorf("closed conn: %s", err)
			default:
				if conn != nil {
					conn.Write([]byte("server error"))
				}
			}

			if conn != nil {
				conn.Close()
			}
		}
	}()

	var lazyLoading LazyLoadingFn = func(name string) (muxer net.Listener, ok bool) {

		if name == "aaa.cpolar.io" {

			// 加载SSL证书
			certificate, err := tls.LoadX509KeyPair("/Users/michael/.acme.sh/cpolar.io_ecc/fullchain.cer", "/Users/michael/.acme.sh/cpolar.io_ecc/cpolar.io.key")
			if err != nil {
				log.Fatal(err)
			}

			// 创建TLS配置
			config := &tls.Config{
				Certificates: []tls.Certificate{certificate},
			}

			//server := &http.Server{
			//	Handler:   httpHandle,
			//	TLSConfig: config,
			//}

			muxer, err := mux.Listen("aaa.cpolar.io")

			if err != nil {
				t.Fatalf("failed to listen on muxer: %v", muxer)
			}

			go listenTLS(t, muxer, config)

			return muxer, true
		}

		return nil, false
	}

	mux.VhostLazyLoader = lazyLoading

	//httpHandle := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	//	io.Copy(w, r.Body)
	//})

	//crt, err := buildTlsCrtFromFile("/Users/michael/.acme.sh/cpolar.io_ecc/fullchain.cer")
	//key, err := buildTlsCrtFromFile("/Users/michael/.acme.sh/cpolar.io_ecc/cpolar.io.key")
	//config, err := addCert(t, crt, key)

	//go http.Serve(muxer,))
	//go server.ServeTLS(muxer, "", "")

	msg := "test"
	respMsg := "404 not found\n"
	url := "https://aaa.cpolar.io:" + port
	//resp, err := http.Post(url, "text/plain", strings.NewReader(msg))
	//if err != nil {
	//	t.Fatalf("failed to post: %v", err)
	//}
	//
	//if resp.StatusCode != 404 {
	//	t.Fatalf("sent incorrect host header, expected 404 but got %d", resp.StatusCode)
	//}

	req, err := http.NewRequest("POST", url, strings.NewReader(msg))
	if err != nil {
		t.Fatalf("failed to construct HTTP request: %v", err)
	}
	req.Host = "aaa.cpolar.io"
	req.Header.Set("Content-Type", "text/plain")

	resp, err := new(http.Client).Do(req)
	if err != nil {
		t.Fatalf("failed to make HTTP request: %v", err)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read: %v", err)
	}

	got := string(body)
	if got != respMsg {
		t.Fatalf("unexpected resposne. got: %v, expected: %v", got, msg)
	}
}

//func createTLSListener(hostName string, tlsConfig *tls.Config) (listener net.Listener, err error) {
//	//创建一个https Listener
//
//	// t.remoteAddrPort = 443
//	listener, err = htl.tlsMux.Listen(hostName)
//	if err != nil {
//		log.Errorf("failed to listen on muxer: %v", htl.listener)
//		return
//	}
//
//	htl.listener = listener
//
//	// listenerTLS := tls.NewListener(listener, tlsConfig)
//
//	if err != nil {
//		log.Errorf(" tlsMux.Listen error:", err)
//		return
//	}
//
//	//go tlsTodo(listenerTLS)
//
//	//需要创建一个全局的TlsListeners，可以通过TunnelId，默认为*.cpolar.io及它的证书
//
//	go htl.listenTLS(listener, tlsConfig)
//
//	//go t.listenTcp(listenerTLS.(*net.TCPListener))
//
//	return listener, nil
//
//}

// Listens for new public tcp connections from the internet.
func listenTLS(t *testing.T, listener net.Listener, tlsCfg *tls.Config) {

	for {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("TlsTunnelListener listenTLS failed with error %v", r)
			}
		}()

		//testHostname := "aaa.cpolar.io"

		// accept public connections
		rawConn, err := listener.Accept()

		if err != nil {

			//// not an error, we're shutting down this tunnel
			//if atomic.LoadInt32(&htl.closing) == 1 {
			//	return
			//}

			t.Errorf("Failed to accept new TCP connection: %v", err)
			continue
		}

		//判断Tunnel限流控制，是否被允许访问新的客户端。
		//if t.limiter.Allow() == false {
		//	log.Warnf("pub conn limiter failed with error tunnel.id=%s", t.Id())
		//	return
		//
		//}

		//conn := conn.Wrap(rawConn, "pub")
		////conn.AddLogPrefix("t.Id", t.Id())
		//conn.Info("New connection from %v", conn.RemoteAddr())

		if tlsCfg != nil {
			rawConn = tls.Server(rawConn, tlsCfg)
		}

		//c, err := TLS(rawConn)
		//if err != nil {
		//	panic(err)
		//}
		//
		//if c.Host() != testHostname {
		//	t.Errorf("Connection Host() is %s, expected %s", c.Host(), testHostname)
		//}

		//if htl.isTunnelServerPort {
		//	go htl.handleTunnelServerConnection(conn)
		//} else {
		//	go htl.HandlePublicConnection(conn)
		//}
		rawConn.Write([]byte(notFound))
		rawConn.Close()
	}
}

////保存tls key到证书仓库
//decodeBytesTlsCrt, err := t.getFileBodyBytes(m.TlsCrt)
//if err != nil {
//return t, err
//}
//
//decodeBytesTlsKey, err := t.getFileBodyBytes(m.TlsKey)
//if err != nil {
//return t, err
//}
//
//t.tlsCfg = &RootTlsConfig{
//TlsCrt: decodeBytesTlsCrt,
//TlsKey: decodeBytesTlsKey,
//}

func buildTlsCrtFromFile(path string) (crt []byte, err error) {
	//1. 读取文件
	fileOrAsset := func(path string) ([]byte, error) {

		loadFn := ioutil.ReadFile

		return loadFn(path)
	}

	usr, _ := user.Current()
	dir := usr.HomeDir

	if path == "~" {
		// In case of "~", which won't be caught by the "else if"
		path = dir
	} else if strings.HasPrefix(path, "~/") {
		// Use strings.HasPrefix so we don't match paths like
		// "/something/~/something/"
		path = filepath.Join(dir, path[2:])
	}

	crt, err = fileOrAsset(path)

	//if err != nil {
	//	return
	//}
	//str = base64.URLEncoding.EncodeToString(crt)

	//str = base64.StdEncoding.EncodeToString(crt)

	//2. 将文件变成byte[]
	//3. 将byte变成base64后的串
	//4. 输出

	//str = crt
	return
}

func testMux(t *testing.T, listen, dial string) {
	muxFn := func(c net.Conn) (Conn, error) {
		return fakeConn{c, dial}, nil
	}

	fakel := make(fakeListener, 1)
	mux, err := NewVhostMuxer(fakel, muxFn, time.Second)
	if err != nil {
		t.Fatalf("failed to start vhost muxer: %v", err)
	}

	l, err := mux.Listen(listen)
	if err != nil {
		t.Fatalf("failed to listen for %s", err)
	}

	done := make(chan struct{})
	go func() {
		conn, err := l.Accept()
		if err != nil {
			t.Fatalf("failed to accept connection: %v", err)
			return
		}

		got := conn.(Conn).Host()
		expected := dial
		if got != expected {
			t.Fatalf("got connection with unexpected host. got: %s, expected: %s", got, expected)
			return
		}

		close(done)
	}()

	go func() {
		_, err := mux.NextError()
		if err != nil {
			t.Fatalf("muxing error: %v", err)
		}
	}()

	fakel <- struct{}{}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatalf("test timed out: dial: %s listen: %s", dial, listen)
	}
}

func TestMuxingPatterns(t *testing.T) {
	var tests = []struct {
		listen string
		dial   string
	}{
		{"example.com", "example.com"},
		{"sub.example.com", "sub.example.com"},
		{"*.example.com", "sub.example.com"},
		{"*.example.com", "nested.sub.example.com"},
	}

	for _, test := range tests {
		testMux(t, test.listen, test.dial)
	}
}

type fakeConn struct {
	net.Conn
	host string
}

func (c fakeConn) SetDeadline(d time.Time) error { return nil }
func (c fakeConn) Host() string                  { return c.host }
func (c fakeConn) Free()                         {}

type fakeNetConn struct {
	net.Conn
}

func (fakeNetConn) SetDeadline(time.Time) error { return nil }

type fakeListener chan struct{}

func (l fakeListener) Accept() (net.Conn, error) {
	for _ = range l {
		return fakeNetConn{nil}, nil
	}
	select {}
}
func (fakeListener) Addr() net.Addr { return nil }
func (fakeListener) Close() error   { return nil }
