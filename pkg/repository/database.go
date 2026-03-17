package repository

import (
	"akrion/pkg/models"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"sync"
	"time"
)

type Repository struct {
	db *gorm.DB
	mu sync.RWMutex
}

// NewRepository создает новое подключение к БД
func NewRepository(dbPath string) (*Repository, error) {
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		return nil, err
	}

	// Автомиграция моделей
	err = db.AutoMigrate(
		&models.TrafficStat{},
		&models.Detection{},
		&models.HoneypotActivity{},
		&models.SystemMetrics{},
	)
	if err != nil {
		return nil, err
	}

	return &Repository{db: db}, nil
}

// SaveTrafficStat сохраняет статистику трафика
func (r *Repository) SaveTrafficStat(stat *models.TrafficStat) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.db.Create(stat).Error
}

// SaveTrafficStatsBatch сохраняет статистику трафика пакетами
func (r *Repository) SaveTrafficStatsBatch(stats []*models.TrafficStat) error {
	if len(stats) == 0 {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.db.CreateInBatches(stats, 100).Error
}

// SaveDetection сохраняет обнаружение
func (r *Repository) SaveDetection(detection *models.Detection) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.db.Create(detection).Error
}

// SaveHoneypotActivity сохраняет активность honeypot
func (r *Repository) SaveHoneypotActivity(activity *models.HoneypotActivity) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.db.Create(activity).Error
}

// SaveSystemMetrics сохраняет системные метрики
func (r *Repository) SaveSystemMetrics(metrics *models.SystemMetrics) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.db.Create(metrics).Error
}

// GetRecentTrafficStats получает последние статистики трафика
func (r *Repository) GetRecentTrafficStats(limit int) ([]models.TrafficStat, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var stats []models.TrafficStat
	err := r.db.Order("timestamp DESC").Limit(limit).Find(&stats).Error
	return stats, err
}

// GetRecentDetections получает последние обнаружения
func (r *Repository) GetRecentDetections(limit int) ([]models.Detection, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var detections []models.Detection
	err := r.db.Order("timestamp DESC").Limit(limit).Find(&detections).Error
	return detections, err
}

// GetRecentHoneypotActivity получает последнюю активность honeypot
func (r *Repository) GetRecentHoneypotActivity(limit int) ([]models.HoneypotActivity, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var activities []models.HoneypotActivity
	err := r.db.Order("timestamp DESC").Limit(limit).Find(&activities).Error
	return activities, err
}

// GetRecentSystemMetrics получает последние системные метрики
func (r *Repository) GetRecentSystemMetrics(limit int) ([]models.SystemMetrics, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var metrics []models.SystemMetrics
	err := r.db.Order("timestamp DESC").Limit(limit).Find(&metrics).Error
	return metrics, err
}

// GetTrafficStatsByTimeRange получает статистику за период
func (r *Repository) GetTrafficStatsByTimeRange(start, end time.Time) ([]models.TrafficStat, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var stats []models.TrafficStat
	err := r.db.Where("timestamp BETWEEN ? AND ?", start, end).Find(&stats).Error
	return stats, err
}

// GetTrafficSummary получает сводку трафика
func (r *Repository) GetTrafficSummary() (map[string]interface{}, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	var totalPackets int64
	var uniqueIPs int64
	var totalDetections int64
	
	r.db.Model(&models.TrafficStat{}).Count(&totalPackets)
	// Raw-запрос для корректного подсчёта уникальных IP в SQLite
	r.db.Raw("SELECT COUNT(DISTINCT src_ip) FROM traffic_stats").Scan(&uniqueIPs)
	r.db.Model(&models.Detection{}).Count(&totalDetections)
	
	return map[string]interface{}{
		"total_packets":    totalPackets,
		"unique_ips":       uniqueIPs,
		"total_detections": totalDetections,
	}, nil
}
