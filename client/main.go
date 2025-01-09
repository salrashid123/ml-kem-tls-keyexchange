package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"reflect"
)

var ()

func main() {

	caCert, err := os.ReadFile("certs/root-ca.crt")
	if err != nil {
		log.Println(err)
		return
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	tlsConfig := &tls.Config{
		ServerName:       "localhost",
		RootCAs:          caCertPool,
		MaxVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{},
	}

	tr := &http.Transport{
		TLSClientConfig: tlsConfig,
	}
	client := &http.Client{Transport: tr}

	resp, err := client.Get("https://localhost:8081")
	if err != nil {
		log.Println(err)
		return
	}

	// https://github.com/golang/go/issues/69241#issuecomment-2329917828
	connState := reflect.ValueOf(*resp.TLS)
	curveIDField := connState.FieldByName("testingOnlyCurveID")

	if !curveIDField.IsValid() {
		return
	}

	fmt.Printf("Group: %s\n", tls.CurveID(curveIDField.Uint()))
	fmt.Printf("CipherSuite: %s\n", tls.CipherSuiteName(resp.TLS.CipherSuite))

	htmlData, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer resp.Body.Close()
	fmt.Printf("%v\n", resp.Status)
	fmt.Println(string(htmlData))

}
