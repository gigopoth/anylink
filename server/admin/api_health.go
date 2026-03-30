package admin

import (
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"time"

	"github.com/bjdgyc/anylink/base"
	"github.com/bjdgyc/anylink/sessdata"
)

var startTime = time.Now()

// HealthCheck returns the health status of the service
func HealthCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	health := map[string]interface{}{
		"status":  "ok",
		"uptime":  time.Since(startTime).String(),
		"time":    time.Now().Format(time.RFC3339),
		"version": base.APP_VER,
	}

	b, _ := json.Marshal(health)
	w.Write(b)
}

// Metrics returns basic metrics in a simple JSON format
// For production use, consider integrating with Prometheus client library
func Metrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	onlineSess := sessdata.OnlineSess()

	metrics := map[string]interface{}{
		"uptime_seconds":     time.Since(startTime).Seconds(),
		"goroutines":         runtime.NumGoroutine(),
		"go_version":         runtime.Version(),
		"online_users":       len(onlineSess),
		"memory_alloc_bytes": memStats.Alloc,
		"memory_sys_bytes":   memStats.Sys,
		"memory_gc_count":    memStats.NumGC,
		"cpu_count":          runtime.NumCPU(),
	}

	b, _ := json.Marshal(metrics)
	w.Write(b)
}

// PrometheusMetrics returns metrics in Prometheus text exposition format
func PrometheusMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	onlineSess := sessdata.OnlineSess()

	fmt.Fprintf(w, "# HELP anylink_uptime_seconds Time since server started in seconds.\n")
	fmt.Fprintf(w, "# TYPE anylink_uptime_seconds gauge\n")
	fmt.Fprintf(w, "anylink_uptime_seconds %f\n", time.Since(startTime).Seconds())

	fmt.Fprintf(w, "# HELP anylink_online_users Number of currently connected VPN users.\n")
	fmt.Fprintf(w, "# TYPE anylink_online_users gauge\n")
	fmt.Fprintf(w, "anylink_online_users %d\n", len(onlineSess))

	fmt.Fprintf(w, "# HELP anylink_goroutines Number of goroutines.\n")
	fmt.Fprintf(w, "# TYPE anylink_goroutines gauge\n")
	fmt.Fprintf(w, "anylink_goroutines %d\n", runtime.NumGoroutine())

	fmt.Fprintf(w, "# HELP anylink_memory_alloc_bytes Current memory allocation in bytes.\n")
	fmt.Fprintf(w, "# TYPE anylink_memory_alloc_bytes gauge\n")
	fmt.Fprintf(w, "anylink_memory_alloc_bytes %d\n", memStats.Alloc)

	fmt.Fprintf(w, "# HELP anylink_memory_sys_bytes Total memory obtained from the OS in bytes.\n")
	fmt.Fprintf(w, "# TYPE anylink_memory_sys_bytes gauge\n")
	fmt.Fprintf(w, "anylink_memory_sys_bytes %d\n", memStats.Sys)

	fmt.Fprintf(w, "# HELP anylink_gc_count Total number of garbage collections.\n")
	fmt.Fprintf(w, "# TYPE anylink_gc_count counter\n")
	fmt.Fprintf(w, "anylink_gc_count %d\n", memStats.NumGC)

	// Per-user bandwidth metrics
	for _, sess := range onlineSess {
		fmt.Fprintf(w, "anylink_user_bandwidth_up{username=%q,group=%q} %s\n",
			sess.Username, sess.Group, sess.BandwidthUpAll)
		fmt.Fprintf(w, "anylink_user_bandwidth_down{username=%q,group=%q} %s\n",
			sess.Username, sess.Group, sess.BandwidthDownAll)
	}
}
