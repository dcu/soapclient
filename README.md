# SoapClient

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
