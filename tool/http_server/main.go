package main

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	var (
		addr    string
		dir     string
		cert    string
		key     string
		handler string
	)
	flag.StringVar(&addr, "addr", ":8001", "http server port")
	flag.StringVar(&dir, "dir", "res", "resource directory path")
	flag.StringVar(&cert, "cert", "", "tls certificate (pem)")
	flag.StringVar(&key, "key", "", "private key (pem)")
	flag.StringVar(&handler, "handler", "/", "web handler")
	flag.Parse()

	switch handler {
	case "/":
	case "":
		handler = "/"
	default: // "a" -> "/a/"
		hRune := []rune(handler)
		if len(hRune) == 1 {
			handler = fmt.Sprintf("/%s/", handler)
		} else {
			r := '/'
			if hRune[0] != r {
				hRune = append([]rune("/"), hRune...)
			}
			if hRune[len(hRune)-1] != r {
				hRune = append(hRune, r)
			}
			handler = string(hRune)
		}
	}

	// for support old operating system
	tlsConfig := tls.Config{
		MinVersion: tls.VersionTLS10, // #nosec
	}
	server := http.Server{
		Addr:              addr,
		TLSConfig:         &tlsConfig,
		ReadHeaderTimeout: time.Minute,
		IdleTimeout:       time.Minute,
	}
	fileServer := http.FileServer(http.Dir(dir))
	handlerFn := func(w http.ResponseWriter, r *http.Request) {
		dumpRequest(r)
		// prevent incorrect cache
		r.Header.Del("If-Modified-Since")
		// redirect for process file directory
		path := strings.Replace(r.URL.Path, handler, "/", 1)
		// prevent directory traversal
		if isDir(filepath.Join(dir, path)) {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		// process compress
		encoding := r.Header.Get("Accept-Encoding")
		switch {
		case strings.Contains(encoding, "gzip"):
			w.Header().Set("Content-Encoding", "gzip")
			gzw := gzip.NewWriter(w)
			defer func() { _ = gzw.Close() }()
			w = &gzipResponseWriter{ResponseWriter: w, w: gzw}
		case strings.Contains(encoding, "deflate"):
			w.Header().Set("Content-Encoding", "deflate")
			dw, _ := flate.NewWriter(w, flate.BestCompression)
			defer func() { _ = dw.Close() }()
			w = &flateResponseWriter{ResponseWriter: w, w: dw}
		}
		// process file
		r.URL.Path = path
		fileServer.ServeHTTP(w, r)
	}
	serveMux := http.NewServeMux()
	serveMux.HandleFunc(handler, handlerFn)
	server.Handler = serveMux

	var err error
	if cert != "" && key != "" {
		err = server.ListenAndServeTLS(cert, key)
	} else {
		err = server.ListenAndServe()
	}
	if err != nil {
		log.Fatalln(err)
	}
}

func dumpRequest(r *http.Request) {
	buf := bytes.NewBuffer(make([]byte, 0, 1024))
	_, _ = fmt.Fprintf(buf, "Remote: %s\n", r.RemoteAddr)
	_, _ = fmt.Fprintf(buf, "%s %s %s", r.Method, r.RequestURI, r.Proto)
	_, _ = fmt.Fprintf(buf, "\nHost: %s", r.Host)
	for k, v := range r.Header {
		_, _ = fmt.Fprintf(buf, "\n%s: %s", k, v[0])
	}
	log.Printf("[handle request]\n%s\n\n", buf)
}

func isDir(path string) bool {
	file, err := os.Open(path) // #nosec
	if err != nil {
		return false
	}
	defer func() { _ = file.Close() }()
	stat, err := file.Stat()
	if err != nil {
		return false
	}
	return stat.IsDir()
}

type gzipResponseWriter struct {
	http.ResponseWriter
	w *gzip.Writer
}

func (rw *gzipResponseWriter) Write(b []byte) (int, error) {
	return rw.w.Write(b)
}

type flateResponseWriter struct {
	http.ResponseWriter
	w *flate.Writer
}

func (rw *flateResponseWriter) Write(b []byte) (int, error) {
	return rw.w.Write(b)
}
