module github.com/aserto-dev/service-host

// replace github.com/aserto-dev/aserto-grpc => ../aserto-grpc

go 1.19

require (
	github.com/aserto-dev/aserto-grpc v0.2.2
	github.com/aserto-dev/certs v0.0.3
	github.com/aserto-dev/go-http-metrics v0.10.1-20221024-1
	github.com/grpc-ecosystem/go-grpc-middleware/providers/prometheus v1.0.0-rc.0
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.16.0
	github.com/pkg/errors v0.9.1
	github.com/prometheus/client_golang v1.16.0
	github.com/rs/cors v1.9.0
	github.com/rs/zerolog v1.29.1
	golang.org/x/sync v0.3.0
	google.golang.org/grpc v1.56.2
	google.golang.org/protobuf v1.31.0
)

require (
	github.com/aserto-dev/logger v0.0.4 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/grpc-ecosystem/go-grpc-middleware/v2 v2.0.0-rc.5 // indirect
	github.com/grpc-ecosystem/go-grpc-prometheus v1.2.0 // indirect
	github.com/magefile/mage v1.15.0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.19 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.4 // indirect
	github.com/prometheus/client_model v0.4.0 // indirect
	github.com/prometheus/common v0.44.0 // indirect
	github.com/prometheus/procfs v0.11.0 // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	go.opencensus.io v0.24.0 // indirect
	golang.org/x/net v0.12.0 // indirect
	golang.org/x/sys v0.10.0 // indirect
	golang.org/x/text v0.11.0 // indirect
	google.golang.org/genproto v0.0.0-20230720185612-659f7aaaa771 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20230720185612-659f7aaaa771 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20230720185612-659f7aaaa771 // indirect
)
