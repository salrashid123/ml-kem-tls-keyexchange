package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"reflect"

	//"net/http/httputil"

	"github.com/gorilla/mux"
	"golang.org/x/net/http2"
)

var ()

const ()

func eventsMiddleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// https://github.com/golang/go/issues/69241#issuecomment-2329917828
		connState := reflect.ValueOf(*r.TLS)
		curveIDField := connState.FieldByName("testingOnlyCurveID")

		if !curveIDField.IsValid() {
			h.ServeHTTP(w, r)
			return
		}

		fmt.Printf("Group: %s\n", tls.CurveID(curveIDField.Uint()))
		fmt.Printf("CipherSuite: %s\n", tls.CipherSuiteName(r.TLS.CipherSuite))

		h.ServeHTTP(w, r)
	})
}

func gethandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "ok")
}

func main() {

	router := mux.NewRouter()
	router.Methods(http.MethodGet).Path("/").HandlerFunc(gethandler)

	tlsConfig := &tls.Config{

		MaxVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{},
	}
	sslKeyLogfile := os.Getenv("SSLKEYLOGFILE")
	if sslKeyLogfile != "" {
		var w *os.File
		w, err := os.OpenFile(sslKeyLogfile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
		if err != nil {
			panic(err)
		}
		tlsConfig.KeyLogWriter = w
	}

	server := &http.Server{
		Addr:      ":8081",
		Handler:   eventsMiddleware(router),
		TLSConfig: tlsConfig,
	}
	http2.ConfigureServer(server, &http2.Server{})
	fmt.Println("Starting Server..")
	err := server.ListenAndServeTLS("certs/localhost.crt", "certs/localhost.key")
	fmt.Printf("Unable to start Server %v", err)

}
