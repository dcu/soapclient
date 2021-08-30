# SoapClient

SoapClient implements a simple SOAP client written in Go.
It is not fully tested against the whole spec so it could not work for your use case.
If that's the case please open an issue to keep track of it.

## Usage

```go
package main

import (
	"crypto/tls"
	"log"

	"github.com/dcu/soapclient"
)

func main() {
	cert, err := tls.LoadX509KeyPair("public.pem", "private.pem")
	if err != nil {
		panic(err)
	}

	client := soapclient.New("URL-HERE", soapclient.ClientOpts{
		Certificate: cert,
		Username:    "FIXME",
		Password:    "FIXME",
	})

	res, err := client.RawQuery(soapclient.Operation{
		Name: "operationName",
		Data: map[string]interface{}{
			"foo": map[string]interface{}{
				"bar":              "baz",
			},
		},
	})
	if err != nil {
		panic(err)
	}

	log.Println("Response:", string(res))
}
```
