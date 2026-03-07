// Package metrics provides Prometheus instrumentation for Connect-RPC services.
package metrics

import (
	"context"
	"time"

	"connectrpc.com/connect"
	"github.com/prometheus/client_golang/prometheus"
)

// NewInterceptor creates a Connect-RPC interceptor that records Prometheus
// metrics for every RPC: duration histogram, in-flight gauge, and total counter.
func NewInterceptor(reg prometheus.Registerer) connect.Interceptor {
	duration := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "pm_rpc_duration_seconds",
		Help:    "RPC duration in seconds.",
		Buckets: prometheus.DefBuckets,
	}, []string{"procedure", "code"})

	inFlight := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "pm_rpc_in_flight",
		Help: "Number of RPCs currently being handled.",
	}, []string{"procedure"})

	total := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "pm_rpc_total",
		Help: "Total number of RPCs completed.",
	}, []string{"procedure", "code"})

	reg.MustRegister(duration, inFlight, total)

	return &interceptor{duration: duration, inFlight: inFlight, total: total}
}

type interceptor struct {
	duration *prometheus.HistogramVec
	inFlight *prometheus.GaugeVec
	total    *prometheus.CounterVec
}

func (i *interceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		proc := req.Spec().Procedure
		i.inFlight.WithLabelValues(proc).Inc()
		start := time.Now()

		resp, err := next(ctx, req)

		code := codeOf(err)
		i.duration.WithLabelValues(proc, code).Observe(time.Since(start).Seconds())
		i.total.WithLabelValues(proc, code).Inc()
		i.inFlight.WithLabelValues(proc).Dec()
		return resp, err
	}
}

func (i *interceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return next // client-side streaming is not used on the server
}

func (i *interceptor) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		proc := conn.Spec().Procedure
		i.inFlight.WithLabelValues(proc).Inc()
		start := time.Now()

		err := next(ctx, conn)

		code := codeOf(err)
		i.duration.WithLabelValues(proc, code).Observe(time.Since(start).Seconds())
		i.total.WithLabelValues(proc, code).Inc()
		i.inFlight.WithLabelValues(proc).Dec()
		return err
	}
}

func codeOf(err error) string {
	if err == nil {
		return "ok"
	}
	return connect.CodeOf(err).String()
}
