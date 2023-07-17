package builder

import (
	"context"
	"fmt"
	"net"
	"net/http"

	"github.com/aserto-dev/certs"
	metrics "github.com/aserto-dev/go-http-metrics/middleware/grpc"
	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-middleware/providers/prometheus"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/cors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
	"google.golang.org/protobuf/encoding/protojson"
)

type ServiceFactory struct{}

func NewServiceFactory() *ServiceFactory {
	return &ServiceFactory{}
}

func (f *ServiceFactory) CreateService(config *API, opts []grpc.ServerOption, registrations GRPCRegistrations,
	handlerRegistrations HandlerRegistrations,
	withGateway bool) (*Server, error) {
	grpcm := grpc_prometheus.NewServerMetrics(
		grpc_prometheus.WithServerCounterOptions(),
	)
	if config.Metrics.ListenAddress != "" {
		exemplarFromContext := func(ctx context.Context) prometheus.Labels {
			method, ok := grpc.Method(ctx)
			if ok {
				return prometheus.Labels{"method": method}
			}
			return nil
		}

		unary := grpc.ChainUnaryInterceptor(grpcm.UnaryServerInterceptor(grpc_prometheus.WithExemplarFromContext(exemplarFromContext)))
		stream := grpc.ChainStreamInterceptor(grpcm.StreamServerInterceptor(grpc_prometheus.WithExemplarFromContext(exemplarFromContext)))

		opts = append(opts, unary, stream)
	}

	grpcServer, err := prepareGrpcServer(&config.GRPC.Certs, opts)
	if err != nil {
		return nil, err
	}
	registrations(grpcServer)
	reflection.Register(grpcServer)

	listener, err := net.Listen("tcp", config.GRPC.ListenAddress)
	if err != nil {
		return nil, err
	}
	gate := Gateway{}
	if withGateway && config.Gateway.ListenAddress != "" {
		gate, err = prepareGateway(config, handlerRegistrations)
		if err != nil {
			return nil, err
		}
	}

	var health *HealthServer
	if config.Health.ListenAddress != "" {
		health = newGRPCHealthServer()
	}
	metric := http.Server{}
	if config.Metrics.ListenAddress != "" {
		mux := http.NewServeMux()
		reg := prometheus.NewRegistry()

		grpcm.InitializeMetrics(grpcServer)
		reg.MustRegister(collectors.NewGoCollector())
		reg.MustRegister(collectors.NewBuildInfoCollector())
		reg.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{ReportErrors: true}))
		reg.MustRegister(grpcm)
		mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))

		// TODO: Fix zpages
		// debugMux := http.NewServeMux()
		// zpages.Handle(debugMux, "/debug")
		// mux.Handle("/debug/", debugMux)

		metric.Handler = mux
		metric.Addr = config.Metrics.ListenAddress
	}
	return &Server{
		Config:        config,
		Server:        grpcServer,
		Listener:      listener,
		Registrations: registrations,
		Gateway:       gate,
		Health:        health,
		Metric:        &metric,
		Started:       make(chan bool),
	}, nil
}

func prepareGateway(config *API, registrations HandlerRegistrations) (Gateway, error) {
	c := cors.New(cors.Options{
		AllowedHeaders: []string{"Authorization", "Content-Type", "Depth"},
		AllowedOrigins: config.Gateway.AllowedOrigins,
		AllowedMethods: []string{http.MethodGet, http.MethodPost, http.MethodHead, http.MethodDelete, http.MethodPut,
			http.MethodPatch, "PROPFIND", "MKCOL", "COPY", "MOVE"},
		Debug: true,
	})

	runtimeMux := gatewayMux()

	tlsCreds, err := certs.GatewayAsClientTLSCreds(config.GRPC.Certs)
	if err != nil {
		return Gateway{}, errors.Wrapf(err, "failed to get TLS credentials")
	}
	grpcEndpoint := fmt.Sprintf("dns:///%s", config.GRPC.ListenAddress)

	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(tlsCreds),
	}

	err = registrations(context.Background(), runtimeMux, grpcEndpoint, opts)
	if err != nil {
		return Gateway{}, err
	}

	mux := http.NewServeMux()
	mux.Handle("/", runtimeMux)
	mux.Handle("/api/", fieldsMaskHandler(runtimeMux))

	gtwServer := &http.Server{
		Addr:              config.Gateway.ListenAddress,
		Handler:           c.Handler(mux),
		ReadTimeout:       config.Gateway.ReadTimeout,
		ReadHeaderTimeout: config.Gateway.ReadHeaderTimeout,
		WriteTimeout:      config.Gateway.WriteTimeout,
		IdleTimeout:       config.Gateway.IdleTimeout,
	}

	return Gateway{Server: gtwServer, Mux: mux, Certs: &config.Gateway.Certs}, nil
}

// gatewayMux creates a gateway multiplexer for serving the API as an OpenAPI endpoint.
func gatewayMux() *runtime.ServeMux {
	return runtime.NewServeMux(
		runtime.WithMetadata(metrics.CaptureGatewayRoute),
		runtime.WithMarshalerOption(
			runtime.MIMEWildcard,
			&runtime.JSONPb{
				MarshalOptions: protojson.MarshalOptions{
					Multiline:       false,
					Indent:          "  ",
					AllowPartial:    true,
					UseProtoNames:   true,
					UseEnumNumbers:  false,
					EmitUnpopulated: true,
				},
				UnmarshalOptions: protojson.UnmarshalOptions{
					AllowPartial:   true,
					DiscardUnknown: true,
				},
			},
		),

		// TODO: figure out if we need a custom error handler or not
		// runtime.WithErrorHandler(CustomErrorHandler),
		runtime.WithMarshalerOption(
			"application/json+masked",
			&runtime.JSONPb{
				MarshalOptions: protojson.MarshalOptions{
					Multiline:       false,
					Indent:          "  ",
					AllowPartial:    true,
					UseProtoNames:   true,
					UseEnumNumbers:  false,
					EmitUnpopulated: false,
				},
				UnmarshalOptions: protojson.UnmarshalOptions{
					AllowPartial:   true,
					DiscardUnknown: true,
				},
			},
		),
	)
}

func prepareGrpcServer(certCfg *certs.TLSCredsConfig, opts []grpc.ServerOption) (*grpc.Server, error) {
	if certCfg != nil && certCfg.TLSCertPath != "" {
		tlsCreds, err := certs.GRPCServerTLSCreds(*certCfg)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to get TLS credentials")
		}
		tlsAuth := grpc.Creds(tlsCreds)
		opts = append(opts, tlsAuth)
	}
	return grpc.NewServer(opts...), nil
}

// fieldsMaskHandler will set the Content-Type to "application/json+masked", which
// will signal the marshaler to not emit unpopulated types, which is needed to
// serialize the masked result set.
// This happens if a fields.mask query parameter is present and set.
func fieldsMaskHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p, ok := r.URL.Query()["fields.mask"]; ok && len(p) > 0 && len(p[0]) > 0 {
			r.Header.Set("Content-Type", "application/json+masked")
		}
		h.ServeHTTP(w, r)
	})
}
