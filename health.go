package builder

import (
	"github.com/aserto-dev/certs"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
)

type Health struct {
	Server     *health.Server
	GRPCServer *grpc.Server
}

// newGRPCHealthServer creates a new HealthServer.
func newGRPCHealthServer(certificates *certs.TLSCredsConfig) *Health {
	healthServer := health.NewServer()
	grpcHealthServer, err := prepareGrpcServer(certificates, nil)
	if err != nil {
		panic(err)
	}

	healthpb.RegisterHealthServer(grpcHealthServer, healthServer)
	reflection.Register(grpcHealthServer)
	return &Health{
		Server:     healthServer,
		GRPCServer: grpcHealthServer,
	}
}

func (h *Health) SetServiceStatus(service string, status healthpb.HealthCheckResponse_ServingStatus) {
	h.Server.SetServingStatus(service, status)
}
