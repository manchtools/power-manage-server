package metrics

import "github.com/prometheus/client_golang/prometheus"

// ConnectedAgentsFunc is a function that returns the number of connected agents.
type ConnectedAgentsFunc func() int

// RegisterGatewayMetrics registers gateway-specific Prometheus metrics.
func RegisterGatewayMetrics(reg prometheus.Registerer, countFn ConnectedAgentsFunc) {
	reg.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "pm_gateway_connected_agents",
		Help: "Number of agents currently connected to the gateway.",
	}, func() float64 {
		return float64(countFn())
	}))
}
