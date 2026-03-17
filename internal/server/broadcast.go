package server

import (
	"log"
	"time"
)

// StartBroadcast запускает горутину для рассылки статистики через WebSocket
func StartBroadcast(deps *Dependencies) {
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			stats := deps.Capture.GetStats()
			sysMetrics, err := deps.SysMonitor.GetCurrentMetrics()
			if err != nil {
				log.Printf("Ошибка получения системных метрик: %v", err)
				continue
			}
			summary, err := deps.Repo.GetTrafficSummary()
			if err != nil {
				log.Printf("Ошибка получения сводки: %v", err)
				continue
			}

			deps.Hub.Broadcast(map[string]interface{}{
				"type": "update",
				"data": map[string]interface{}{
					"packet_stats": stats,
					"system":       sysMetrics,
					"summary":      summary,
				},
			})
		}
	}()
}
