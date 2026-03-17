package monitor

import (
	"akrion/pkg/repository"
	"context"
	"log"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/mem"
)

// SystemMonitor мониторит системные ресурсы
type SystemMonitor struct {
	repo     *repository.Repository
	interval time.Duration
	stopChan chan struct{}
}

// NewSystemMonitor создает новый монитор системы
func NewSystemMonitor(repo *repository.Repository, interval time.Duration) *SystemMonitor {
	return &SystemMonitor{
		repo:     repo,
		interval: interval,
		stopChan: make(chan struct{}),
	}
}

// Start начинает мониторинг системы
func (sm *SystemMonitor) Start() {
	ticker := time.NewTicker(sm.interval)
	defer ticker.Stop()

	log.Println("Системный мониторинг запущен")

	for {
		select {
		case <-sm.stopChan:
			return
		case <-ticker.C:
			sm.collectMetrics()
		}
	}
}

// Stop останавливает мониторинг
func (sm *SystemMonitor) Stop() {
	close(sm.stopChan)
}

// collectMetrics собирает системные метрики (только для логирования, не сохраняет в БД)
func (sm *SystemMonitor) collectMetrics() {
	// Метрики собираются только по запросу через GetCurrentMetrics()
	// Не сохраняем историю в БД, чтобы не засорять базу данных
}

// GetCurrentMetrics возвращает текущие метрики системы
func (sm *SystemMonitor) GetCurrentMetrics() (map[string]interface{}, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cpuPercent, err := cpu.PercentWithContext(ctx, time.Second, false)
	if err != nil {
		return nil, err
	}

	memInfo, err := mem.VirtualMemoryWithContext(ctx)
	if err != nil {
		return nil, err
	}

	var avgCPU float64
	if len(cpuPercent) > 0 {
		avgCPU = cpuPercent[0]
	}

	return map[string]interface{}{
		"cpu_percent": avgCPU,
		"ram_used":    memInfo.Used,
		"ram_total":    memInfo.Total,
		"ram_percent":  memInfo.UsedPercent,
		"ram_free":     memInfo.Free,
		"timestamp":    time.Now(),
	}, nil
}
