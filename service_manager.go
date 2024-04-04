package builder

import (
	"context"
	"net"
	"net/http"
	"reflect"
	"time"

	ocprometheus "contrib.go.opencensus.io/exporter/prometheus"
	"github.com/aserto-dev/certs"
	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-middleware/providers/prometheus"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"
	"go.opencensus.io/plugin/ocgrpc"
	"go.opencensus.io/stats/view"
	"go.opencensus.io/zpages"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
)

type ServiceManager struct {
	Context  context.Context
	logger   *zerolog.Logger
	errGroup *errgroup.Group

	Servers         map[string]*Server
	DependencyMap   map[string][]string
	HealthServer    *Health
	MetricServer    *http.Server
	shutdownTimeout int // timeout to force stop services in seconds
}

func NewServiceManager(logger *zerolog.Logger) *ServiceManager {

	serviceLogger := logger.With().Str("component", "service-manager").Logger()
	errGroup, ctx := errgroup.WithContext(context.Background())
	return &ServiceManager{
		Context:         ctx,
		logger:          &serviceLogger,
		Servers:         make(map[string]*Server),
		DependencyMap:   make(map[string][]string),
		errGroup:        errGroup,
		shutdownTimeout: 30,
	}
}

func (s *ServiceManager) WithShutdownTimeout(seconds int) *ServiceManager {
	s.shutdownTimeout = seconds
	return s
}

func (s *ServiceManager) AddGRPCServer(server *Server) error {
	s.Servers[server.Config.GRPC.ListenAddress] = server
	return nil
}

func (s *ServiceManager) SetupHealthServer(address string, crts *certs.TLSCredsConfig) error {
	healthServer := newGRPCHealthServer(crts)
	s.HealthServer = healthServer
	healthListener, err := net.Listen("tcp", address)
	s.logger.Info().Msgf("Starting %s Health server", address)
	if err != nil {
		return err
	}
	s.errGroup.Go(func() error {
		return healthServer.GRPCServer.Serve(healthListener)
	})
	return nil
}

func (s *ServiceManager) SetupMetricsServer(address string, crts *certs.TLSCredsConfig, enableZPages bool) ([]grpc.ServerOption, error) {
	metric := http.Server{
		ReadTimeout:       2 * time.Second,
		ReadHeaderTimeout: 2 * time.Second,
		WriteTimeout:      2 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	s.MetricServer = &metric
	mux := http.NewServeMux()
	reg := prometheus.NewRegistry()

	grpcm := grpc_prometheus.NewServerMetrics(
		grpc_prometheus.WithServerCounterOptions(),
	)
	reg.MustRegister(collectors.NewGoCollector())
	reg.MustRegister(collectors.NewBuildInfoCollector())
	reg.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{ReportErrors: true}))
	reg.MustRegister(grpcm)
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{
		Registry: reg,
	}))
	if enableZPages {
		zpages.Handle(mux, "/debug")
		ocexporter, err := ocprometheus.NewExporter(ocprometheus.Options{
			Registry: reg,
		})
		if err != nil {
			return nil, err
		}
		view.RegisterExporter(ocexporter)
		err = view.Register(ocgrpc.DefaultServerViews...)
		if err != nil {
			return nil, err
		}
	}

	metric.Handler = mux
	metric.Addr = address
	if crts == nil {
		s.errGroup.Go(metric.ListenAndServe)
	} else {
		s.errGroup.Go(func() error {
			return metric.ListenAndServeTLS(crts.TLSCertPath, crts.TLSKeyPath)
		})
	}

	exemplarFromContext := func(ctx context.Context) prometheus.Labels {
		method, ok := grpc.Method(ctx)

		if ok {
			return prometheus.Labels{"method": method}
		}
		return nil
	}

	var opts []grpc.ServerOption

	unary := grpc.ChainUnaryInterceptor(grpcm.UnaryServerInterceptor(grpc_prometheus.WithExemplarFromContext(exemplarFromContext)))
	stream := grpc.ChainStreamInterceptor(grpcm.StreamServerInterceptor(grpc_prometheus.WithExemplarFromContext(exemplarFromContext)))
	opts = append(opts, unary, stream, grpc.StatsHandler(&ocgrpc.ServerHandler{}))
	return opts, nil
}

func (s *ServiceManager) StartServers(ctx context.Context) error {
	for serverAddress, value := range s.Servers {
		address := serverAddress
		serverDetails := value

		// log all service details.
		s.logDetails(address, &serverDetails.Config.GRPC)
		s.logDetails(address, &serverDetails.Config.Gateway)

		s.errGroup.Go(func() error {
			if dependesOnArray, ok := s.DependencyMap[address]; ok {
				for _, dependesOn := range dependesOnArray {
					s.logger.Info().Msgf("%s waiting for %s", address, dependesOn)
					<-s.Servers[dependesOn].Started // wait for started from the dependenent service.
				}
			}
			grpcServer := serverDetails.Server
			listener := serverDetails.Listener
			s.logger.Info().Msgf("Starting %s GRPC server", address)
			s.errGroup.Go(func() error {
				return grpcServer.Serve(listener)
			})

			httpServer := serverDetails.Gateway
			if httpServer.Server != nil {
				s.errGroup.Go(func() error {
					s.logger.Info().Msgf("Starting %s Gateway server", httpServer.Server.Addr)
					if httpServer.Certs == nil || httpServer.Certs.TLSCertPath == "" {
						err := httpServer.Server.ListenAndServe()
						if err != nil {
							return err
						}
					}
					if httpServer.Certs.TLSCertPath != "" {
						err := httpServer.Server.ListenAndServeTLS(httpServer.Certs.TLSCertPath, httpServer.Certs.TLSKeyPath)
						if err != nil {
							return err
						}
					}
					return nil
				})
			}

			serverDetails.Started <- true // send started information.
			return nil
		})
	}
	return nil
}

func (s *ServiceManager) logDetails(address string, element interface{}) {
	ref := reflect.ValueOf(element).Elem()
	typeOfT := ref.Type()

	for i := 0; i < ref.NumField(); i++ {
		f := ref.Field(i)
		s.logger.Debug().Str("address", address).Msgf("%s = %v\n", typeOfT.Field(i).Name, f.Interface())
	}
}

func (s *ServiceManager) StopServers(ctx context.Context) {
	timeout := time.Duration(s.shutdownTimeout) * time.Second
	timeoutContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if s.HealthServer != nil {
		s.logger.Info().Msg("Stopping health server")
		if !shutDown(s.HealthServer.GRPCServer, timeout) {
			s.logger.Warn().Msg("Stopped health server forcefully")
		}
	}
	if s.MetricServer != nil {
		s.logger.Info().Msg("Stopping metric server")
		err := s.MetricServer.Shutdown(timeoutContext)
		if err != nil {
			s.logger.Err(err).Msg("failed to shutdown metric server")
			s.logger.Debug().Msg("forcefully closing metric server")
			if err := s.MetricServer.Close(); err != nil {
				s.logger.Err(err).Msg("failed to close the metric server")
			}
		}
	}
	for address, value := range s.Servers {
		s.logger.Info().Msgf("Stopping %s GRPC server", address)
		if !shutDown(value.Server, timeout) {
			s.logger.Warn().Msgf("Stopped %s GRPC forcefully", address)
		}
		if value.Gateway.Server != nil {
			s.logger.Info().Msgf("Stopping %s Gateway server", value.Gateway.Server.Addr)
			err := value.Gateway.Server.Shutdown(timeoutContext)
			if err != nil {
				s.logger.Err(err).Msgf("failed to shutdown gateway for %s", address)
				s.logger.Debug().Msgf("forcefully closing gateway %s", address)
				if err := value.Gateway.Server.Close(); err != nil {
					s.logger.Err(err).Msgf("failed to close gateway server %s", address)
				}
			}
		}
		for _, cleanup := range value.Cleanup {
			s.logger.Info().Msgf("Running cleanups for %s", address)
			cleanup()
		}
	}
}

func shutDown(server *grpc.Server, timeout time.Duration) bool {
	result := make(chan bool, 1)
	go func() {
		server.GracefulStop()
		result <- true
	}()
	select {
	case <-time.After(timeout):
		server.Stop()
		return false
	case response := <-result:
		return response
	}
}
