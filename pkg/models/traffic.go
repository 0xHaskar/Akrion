package models

import (
	"time"
	"gorm.io/gorm"
)

// TrafficStat хранит статистику трафика
type TrafficStat struct {
	ID          uint      `gorm:"primaryKey" json:"id"`
	Timestamp   time.Time `json:"timestamp"`
	Protocol    string    `json:"protocol"`
	SrcIP       string    `json:"src_ip"`
	DstIP       string    `json:"dst_ip"`
	SrcPort     int       `json:"src_port"`
	DstPort     int       `json:"dst_port"`
	PacketCount int64     `json:"packet_count"`
	CreatedAt   time.Time `json:"created_at"`
}

// Detection хранит обнаруженные аномалии
type Detection struct {
	ID          uint      `gorm:"primaryKey" json:"id"`
	Timestamp   time.Time `json:"timestamp"`
	Type        string    `json:"type"` // "port_scan", "suspicious_activity", etc.
	SrcIP       string    `json:"src_ip"`
	DstIP       string    `json:"dst_ip"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"` // "low", "medium", "high"
	CreatedAt   time.Time `json:"created_at"`
}

// HoneypotActivity хранит активность honeypot
type HoneypotActivity struct {
	ID          uint      `gorm:"primaryKey" json:"id"`
	Timestamp   time.Time `json:"timestamp"`
	SrcIP       string    `json:"src_ip"`
	DstPort     int       `json:"dst_port"`
	Protocol    string    `json:"protocol"`
	Action      string    `json:"action"` // "connection", "scan", etc.
	CreatedAt   time.Time `json:"created_at"`
}

// SystemMetrics хранит системные метрики
type SystemMetrics struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	Timestamp time.Time `json:"timestamp"`
	CPUPercent float64  `json:"cpu_percent"`
	RAMUsed   uint64    `json:"ram_used"`   // в байтах
	RAMTotal  uint64    `json:"ram_total"`  // в байтах
	RAMPercent float64  `json:"ram_percent"`
	CreatedAt time.Time `json:"created_at"`
}

// BeforeCreate хуки для установки CreatedAt
func (t *TrafficStat) BeforeCreate(tx *gorm.DB) error {
	t.CreatedAt = time.Now()
	return nil
}

func (d *Detection) BeforeCreate(tx *gorm.DB) error {
	d.CreatedAt = time.Now()
	return nil
}

func (h *HoneypotActivity) BeforeCreate(tx *gorm.DB) error {
	h.CreatedAt = time.Now()
	return nil
}

func (s *SystemMetrics) BeforeCreate(tx *gorm.DB) error {
	s.CreatedAt = time.Now()
	return nil
}
