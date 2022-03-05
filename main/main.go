package main

import (
	"log"
	"os"
    "net"
    "context"
    "time"

	"github.com/things-go/go-socks5"
)


func main() {
    port := os.Getenv("PROXY_PORT")
    dnsServer := os.Getenv("DNS_SERVER")
    var r *net.Resolver
    r = &net.Resolver{
        PreferGo: true,
        Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
            d := net.Dialer{
                Timeout: time.Millisecond * time.Duration(10000),
            }
            return d.DialContext(ctx, network, dnsServer+":53")
        },
    }
    creds := socks5.StaticCredentials{}
    cator := socks5.UserPassAuthenticator{Credentials: creds}
    server := socks5.NewServer(
                socks5.WithAuthMethods([]socks5.Authenticator{cator}),
                socks5.WithLogger(socks5.NewLogger(log.New(os.Stdout, "", log.LstdFlags))),
                socks5.WithResolver(socks5.NewSocksResolver(r)),
    )

    log.Printf("Start listening proxy service on port: [%s]\n", port)
    log.Printf("DNS server: [%s]\n", dnsServer)
    log.Printf("Akeyless GW URL: [%s]\n", os.Getenv("AKEYLESS_GW_URL"))
    log.Printf("Allowed Access IDs: [%s]\n", os.Getenv("ALLOWED_ACCESS_IDS"))
    if err := server.ListenAndServe("tcp", ":"+port); err != nil {
        log.Fatal(err)
    }
}

