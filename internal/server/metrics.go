package server

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// metrics uses a private registry. Every label is drawn from a fixed set
// (route templates, methods, status classes); nothing derived from a request
// value — token, ID, IP, path — is ever a label. There is deliberately no
// gauge of live Secrets: polling it would time individual creations and reads.
type metrics struct {
	reg           *prometheus.Registry
	created       prometheus.Counter
	views         prometheus.Counter
	failedUnlocks prometheus.Counter
	destroyed     prometheus.Counter
	revocations   prometheus.Counter
	goneReads     prometheus.Counter
	storeErrors   prometheus.Counter
	rateLimited   *prometheus.CounterVec
	duration      *prometheus.HistogramVec
	kdfWait       prometheus.Histogram
}

func newMetrics() *metrics {
	reg := prometheus.NewRegistry()
	f := func(name, help string) prometheus.Counter {
		c := prometheus.NewCounter(prometheus.CounterOpts{Name: name, Help: help})
		reg.MustRegister(c)
		return c
	}
	m := &metrics{
		reg:           reg,
		created:       f("secrets_created_total", "Secrets created."),
		views:         f("views_total", "Successful Views."),
		failedUnlocks: f("failed_unlocks_total", "Failed Unlocks (wrong Passphrase)."),
		destroyed:     f("secrets_destroyed_total", "Secrets destroyed by reaching the Failed Unlock limit."),
		revocations:   f("revocations_total", "Secrets revoked by their creator."),
		goneReads:     f("gone_reads_total", "Reads of a Secret that is Gone or never existed."),
		storeErrors:   f("store_errors_total", "Errors talking to the store."),
		rateLimited: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "rate_limited_total", Help: "Requests rejected by the rate limiter.",
		}, []string{"route"}),
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "Request latency by route template.",
			Buckets: []float64{.001, .0025, .005, .01, .025, .05, .1, .25, .5, 1, 2.5},
		}, []string{"route", "method", "status_class"}),
		kdfWait: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "kdf_wait_seconds",
			Help:    "Time spent queued for an Argon2id slot.",
			Buckets: []float64{.0001, .001, .005, .01, .025, .05, .1, .25, .5, 1},
		}),
	}
	reg.MustRegister(m.rateLimited, m.duration, m.kdfWait, collectors.NewGoCollector())
	return m
}

func (m *metrics) handler() http.Handler {
	return promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{})
}

func statusClass(code int) string {
	switch {
	case code >= 500:
		return "5xx"
	case code >= 400:
		return "4xx"
	case code >= 300:
		return "3xx"
	default:
		return "2xx"
	}
}
