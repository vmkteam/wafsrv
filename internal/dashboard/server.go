package dashboard

//go:generate zenrpc

import (
	"net/http"

	"wafsrv/internal/waf/event"
	"wafsrv/internal/waf/filter"
	"wafsrv/internal/waf/ip"
	"wafsrv/internal/waf/proxy"

	"github.com/vmkteam/zenrpc/v2"
)

const (
	NSStatus  = "status"
	NSBlock   = "block"
	NSAttack  = "attack"
	NSEvents  = "events"
	NSMetrics = "metrics"
	NSFilter  = "filter"
	NSConfig  = "config"
)

var (
	ErrBadRequest = zenrpc.NewStringError(http.StatusBadRequest, "bad request")
	ErrNotFound   = zenrpc.NewStringError(http.StatusNotFound, "not found")
	ErrInternal   = zenrpc.NewStringError(http.StatusInternalServerError, "internal error")
)

// New creates a new management JSON-RPC server.
func New(ipService *ip.Service, cfg StatusInfo, p *proxy.Proxy, attackSvc *AttackService, recorder *event.Recorder, trafficFilter *filter.TrafficFilter, configResp ConfigResponse) *zenrpc.Server {
	rpc := zenrpc.NewServer(zenrpc.Options{
		ExposeSMD: true,
		AllowCORS: true,
	})

	rpc.RegisterAll(map[string]zenrpc.Invoker{
		NSStatus:  NewStatusService(cfg, p),
		NSBlock:   NewBlockService(ipService),
		NSAttack:  attackSvc,
		NSEvents:  NewEventsService(recorder),
		NSMetrics: NewMetricsService(recorder, ipService),
		NSFilter:  NewFilterService(trafficFilter),
		NSConfig:  NewConfigService(configResp),
	})

	return rpc
}
