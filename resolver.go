package socks5

import (
	"context"
	"net"
)

func NewSocksResolver(r *net.Resolver) NameResolver {
	if r == nil {
		return DNSResolver{}
	}
	return socksResolver{r}
}

type socksResolver struct {
	*net.Resolver
}

func (sr socksResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	ips, err := sr.Resolver.LookupIPAddr(ctx, name)
	if err != nil {
		return ctx, nil, err
	}
	if len(ips) == 0 {
		return ctx, nil, &net.DNSError{Err: "no such host", Name: name}
	}
	return ctx, ips[0].IP, nil
}

// NameResolver is used to implement custom name resolution
type NameResolver interface {
	Resolve(ctx context.Context, name string) (context.Context, net.IP, error)
}

// DNSResolver uses the system DNS to resolve host names
type DNSResolver struct{}

// Resolve implement interface NameResolver
func (d DNSResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	addr, err := net.ResolveIPAddr("ip", name)
	if err != nil {
		return ctx, nil, err
	}
	return ctx, addr.IP, err
}
