package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	cgrpc "github.com/asim/go-micro/plugins/client/grpc/v3"
	"github.com/asim/go-micro/plugins/registry/etcd/v3"
	"github.com/asim/go-micro/v3"
	ahandler "github.com/asim/go-micro/v3/api/handler"
	aapi "github.com/asim/go-micro/v3/api/handler/api"
	"github.com/asim/go-micro/v3/api/handler/event"
	ahttp "github.com/asim/go-micro/v3/api/handler/http"
	arpc "github.com/asim/go-micro/v3/api/handler/rpc"
	"github.com/asim/go-micro/v3/api/handler/web"
	"github.com/asim/go-micro/v3/api/resolver"
	"github.com/asim/go-micro/v3/api/resolver/grpc"
	"github.com/asim/go-micro/v3/api/resolver/host"
	"github.com/asim/go-micro/v3/api/resolver/path"
	"github.com/asim/go-micro/v3/api/router"
	regRouter "github.com/asim/go-micro/v3/api/router/registry"
	"github.com/asim/go-micro/v3/api/server"
	"github.com/asim/go-micro/v3/api/server/acme/autocert"
	httpapi "github.com/asim/go-micro/v3/api/server/http"
	"github.com/asim/go-micro/v3/logger"
	"github.com/gorilla/mux"
	"github.com/urfave/cli/v2"
)

var (
	Name                  = "go.micro.api"
	Address               = ":8080"
	Handler               = "meta"
	Resolver              = "micro"
	RPCPath               = "/rpc"
	APIPath               = "/"
	ProxyPath             = "/{service:[a-zA-Z0-9]+}"
	Namespace             = "go.micro"
	HeaderPrefix          = "X-Micro-"
	EnableRPC             = false
	ACMEProvider          = "autocert"
	ACMEChallengeProvider = "cloudflare"
)

func Run(ctx *cli.Context) error {
	options, err := parseOptions(ctx)
	if err != nil {
		return err
	}

	srv := micro.NewService(micro.Name(options.Name), micro.Registry(etcd.NewRegistry()), micro.Client(cgrpc.NewClient()))
	var opts []server.Option
	if options.EnableACME {
		opts = append(opts, server.EnableACME(true))
		opts = append(opts, server.ACMEHosts(options.ACMEHosts...))
		switch options.ACMEProvider {
		case "autocert":
			opts = append(opts, server.ACMEProvider(autocert.NewProvider()))
		default:
			return fmt.Errorf("%s is not a valid ACME provider", options.ACMEProvider)
		}
	} else if options.EnableTLS {
		config, err := TLSConfig(ctx)
		if err != nil {
			return err
		}
		opts = append(opts, server.EnableTLS(true))
		opts = append(opts, server.TLSConfig(config))
	}

	if options.EnableCors {
		opts = append(opts, server.EnableCORS(true))
	}

	// create the router
	var h http.Handler
	r := mux.NewRouter()
	h = r

	// if options.EnableStats {
	// 	st := stats.New()
	// 	r.HandleFunc("/stats", st.StatsHandler)
	// 	h = st.ServeHTTP(r)
	// 	st.Start()
	// 	defer st.Stop()
	// }

	// return version and list of services
	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "OPTIONS" {
			return
		}
		response := fmt.Sprintf(`{"version": "%s"}`, ctx.App.Version)
		w.Write([]byte(response))
	})

	// strip favicon.ico
	r.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {})

	// resolver options
	ropts := []resolver.Option{
		resolver.WithNamespace(resolver.StaticNamespace(options.Namespace)),
		resolver.WithHandler(options.Handler),
	}

	// default resolver
	// rr := rrmicro.NewResolver(ropts...)
	var rr resolver.Resolver

	switch options.Resolver {
	case "host":
		rr = host.NewResolver(ropts...)
	case "path":
		rr = path.NewResolver(ropts...)
	case "grpc":
		rr = grpc.NewResolver(ropts...)
	}

	// register rpc handler
	// if options.EnableRPC {
	// 	logger.Infof("Registering RPC Handler at %s", RPCPath)
	// 	r.Handle(RPCPath, handler.NewRPCHandler(rr))
	// }

	switch options.Handler {
	case "rpc":
		logger.Infof("Registering API RPC Handler at %s", APIPath)
		rt := regRouter.NewRouter(
			router.WithHandler(arpc.Handler),
			router.WithResolver(rr),
			router.WithRegistry(srv.Options().Registry),
		)
		rp := arpc.NewHandler(
			ahandler.WithNamespace(Namespace),
			ahandler.WithRouter(rt),
			ahandler.WithClient(srv.Client()),
		)
		r.PathPrefix(APIPath).Handler(rp)
	case "api":
		logger.Infof("Registering API Request Handler at %s", APIPath)
		rt := regRouter.NewRouter(
			router.WithHandler(aapi.Handler),
			router.WithResolver(rr),
			router.WithRegistry(srv.Options().Registry),
		)
		ap := aapi.NewHandler(
			ahandler.WithNamespace(Namespace),
			ahandler.WithRouter(rt),
			ahandler.WithClient(srv.Client()),
		)
		r.PathPrefix(APIPath).Handler(ap)
	case "event":
		logger.Infof("Registering API Event Handler at %s", APIPath)
		rt := regRouter.NewRouter(
			router.WithHandler(event.Handler),
			router.WithResolver(rr),
			router.WithRegistry(srv.Options().Registry),
		)
		ev := event.NewHandler(
			ahandler.WithNamespace(Namespace),
			ahandler.WithRouter(rt),
			ahandler.WithClient(srv.Client()),
		)
		r.PathPrefix(APIPath).Handler(ev)
	case "http", "proxy":
		logger.Infof("Registering API HTTP Handler at %s", ProxyPath)
		rt := regRouter.NewRouter(
			router.WithHandler(ahttp.Handler),
			router.WithResolver(rr),
			router.WithRegistry(srv.Options().Registry),
		)
		ht := ahttp.NewHandler(
			ahandler.WithNamespace(Namespace),
			ahandler.WithRouter(rt),
			ahandler.WithClient(srv.Client()),
		)
		r.PathPrefix(ProxyPath).Handler(ht)
	case "web":
		logger.Infof("Registering API Web Handler at %s", APIPath)
		rt := regRouter.NewRouter(
			router.WithHandler(web.Handler),
			router.WithResolver(rr),
			router.WithRegistry(srv.Options().Registry),
		)
		w := web.NewHandler(
			ahandler.WithNamespace(Namespace),
			ahandler.WithRouter(rt),
			ahandler.WithClient(srv.Client()),
		)
		r.PathPrefix(APIPath).Handler(w)
	default:
		logger.Infof("Registering API Default Handler at %s", APIPath)
		// rt := regRouter.NewRouter(
		// 	router.WithResolver(rr),
		// 	router.WithRegistry(srv.Options().Registry),
		// )
		// r.PathPrefix(APIPath).Handler(handler.Meta(srv, rt, Namespace))
	}

	// create the auth wrapper and the server
	// authWrapper := auth.Wrapper(rr, Namespace)
	// api := httpapi.NewServer(Address, server.WrapHandler(authWrapper))
	api := httpapi.NewServer(Address)

	api.Init(opts...)
	api.Handle("/", h)

	// Start API
	if err := api.Start(); err != nil {
		logger.Fatal(err)
	}

	// srv.Init()
	// Run server
	if err := srv.Run(); err != nil {
		logger.Fatal(err)
	}

	// Stop API
	if err := api.Stop(); err != nil {
		logger.Fatal(err)
	}
	return nil
}

func parseOptions(ctx *cli.Context) (Options, error) {
	opts := Options{Name: name, Namespace: "go.micro", Address: ":8080"}
	if name := ctx.String("server_name"); len(name) > 0 {
		opts.Name = name
	}
	if namespace := ctx.String("namespace"); len(namespace) > 0 {
		opts.Namespace = namespace
	}
	if address := ctx.String("address"); len(address) > 0 {
		opts.Address = address
	}
	if handler := ctx.String("handler"); len(handler) > 0 {
		opts.Handler = handler
	}
	if resolver := ctx.String("resolver"); len(resolver) > 0 {
		opts.Resolver = resolver
	}
	opts.EnableRPC = ctx.Bool("enable_rpc")
	opts.EnableACME = ctx.Bool("enable_acme")
	if acme := ctx.String("acme_provider"); len(acme) > 0 {
		opts.ACMEProvider = acme
	}
	opts.EnableTLS = ctx.Bool("enable_tls")
	opts.EnableStats = ctx.Bool("enable_stats")
	for _, host := range strings.Split(ctx.String("acme_hosts"), ",") {
		if len(host) > 0 {
			opts.ACMEHosts = append(opts.ACMEHosts, host)
		}
	}
	return opts, nil
}

func TLSConfig(ctx *cli.Context) (*tls.Config, error) {
	cert := ctx.String("tls_cert_file")
	key := ctx.String("tls_key_file")
	ca := ctx.String("tls_client_ca_file")

	if len(cert) > 0 && len(key) > 0 {
		certs, err := tls.LoadX509KeyPair(cert, key)
		if err != nil {
			return nil, err
		}

		if len(ca) > 0 {
			caCert, err := ioutil.ReadFile(ca)
			if err != nil {
				return nil, err
			}

			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM(caCert)

			return &tls.Config{
				Certificates: []tls.Certificate{certs},
				ClientCAs:    caCertPool,
				ClientAuth:   tls.RequireAndVerifyClientCert,
				NextProtos:   []string{"h2", "http/1.1"},
			}, nil
		}

		return &tls.Config{
			Certificates: []tls.Certificate{certs}, NextProtos: []string{"h2", "http/1.1"},
		}, nil
	}

	return nil, errors.New("TLS certificate and key files not specified")
}
