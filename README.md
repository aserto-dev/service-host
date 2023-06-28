# Service-host package

This is a very basic package that allows users to create and manage GRPC and REST services. 

The service factory allows creating a service instance based on the API configuration. 
The service manager allows controlling multiple services and provides basic dependency management.

Example of a very basic eds reader service creation and start:
```
...
edgeAPI  := builder.API{}
edgeAPI.GRPC.ListenAddress  =  "localhost:8080"
edgeAPI.Gateway.ListenAddress  =  "localhost:8081"

edgeDir, err  := eds.New(&directory.Config{DBPath: "/tmp/my.db", Seed: true}, &logger)
if err !=  nil {
  log.Fatal(err)
}

edgeReader, err  := factoryInstance.CreateService(&edgeAPI, opts, func(server *grpc.Server) {
reader.RegisterReaderServer(server, edgeDir)
}, func(ctx context.Context, mux *runtime.ServeMux, grpcEndpoint string, opts []grpc.DialOption) error {
return reader.RegisterReaderHandlerFromEndpoint(ctx, mux, grpcEndpoint, opts)
}, true)

if err !=  nil {
log.Fatal(err)
}
managerInstance.AddGRPCServer(edgeReader)
managerInstance.StartServers(ctx)
...
```