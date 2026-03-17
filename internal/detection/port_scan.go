package detection

import (
	"akrion/pkg/models"
	"akrion/pkg/repository"
	"fmt"
	"log"
	"sync"
	"time"
)

const (
	// MaxPortsAllowed максимальное количество портов от одного IP до алерта
	MaxPortsAllowed = 2
	alertCooldown   = 5 * time.Minute
)

// PortScanDetector обнаруживает сканирование портов по TCP SYN пакетам
type PortScanDetector struct {
	repo          *repository.Repository
	localIP       string
	mu            sync.RWMutex
	packetsByIP   map[string]map[int]int64 // IP -> порт -> количество пакетов
	totalPackets  int64
	detectedIPs   map[string]bool
	lastAlertTime map[string]time.Time
}

// NewPortScanDetector создаёт детектор сканирования портов
func NewPortScanDetector(repo *repository.Repository, localIP string) *PortScanDetector {
	return &PortScanDetector{
		repo:          repo,
		localIP:       localIP,
		packetsByIP:   make(map[string]map[int]int64),
		detectedIPs:   make(map[string]bool),
		lastAlertTime: make(map[string]time.Time),
	}
}

// OnPacket вызывается для каждого захваченного TCP SYN пакета
func (d *PortScanDetector) OnPacket(srcIP, dstIP string, srcPort, dstPort int) {
	d.mu.Lock()
	d.totalPackets++

	if d.packetsByIP[srcIP] == nil {
		d.packetsByIP[srcIP] = make(map[int]int64)
	}

	portWasNew := d.packetsByIP[srcIP][dstPort] == 0
	d.packetsByIP[srcIP][dstPort]++

	uniquePorts := len(d.packetsByIP[srcIP])
	shouldAlert := uniquePorts > MaxPortsAllowed && portWasNew
	d.mu.Unlock()

	if shouldAlert {
		d.checkPortScan(srcIP, uniquePorts)
	}
}

func (d *PortScanDetector) checkPortScan(srcIP string, portCount int) {
	d.mu.Lock()

	if lastAlert, exists := d.lastAlertTime[srcIP]; exists {
		if time.Since(lastAlert) < alertCooldown {
			d.mu.Unlock()
			log.Printf("[~] Пропущен алерт для %s (слишком рано после последнего)", srcIP)
			return
		}
	}

	if d.detectedIPs[srcIP] {
		log.Printf("[~] IP %s уже был обнаружен ранее, создаем новое обнаружение", srcIP)
	}

	d.detectedIPs[srcIP] = true
	d.lastAlertTime[srcIP] = time.Now()
	d.mu.Unlock()

	detection := &models.Detection{
		Timestamp:   time.Now(),
		Type:        "port_scan",
		SrcIP:       srcIP,
		DstIP:       d.localIP,
		Description: fmt.Sprintf("Обнаружено сканирование портов: %d уникальных портов", portCount),
		Severity:    "medium",
	}

	go func() {
		if err := d.repo.SaveDetection(detection); err != nil {
			log.Printf("Ошибка сохранения обнаружения: %v", err)
		} else {
			log.Printf("[✓] Обнаружение сохранено в БД для %s", srcIP)
		}
	}()

	log.Printf("[!] ОБНАРУЖЕНО сканирование портов от %s (%d уникальных портов)", srcIP, portCount)
}

// GetStats возвращает текущую статистику
func (d *PortScanDetector) GetStats() map[string]interface{} {
	d.mu.RLock()
	defer d.mu.RUnlock()

	return map[string]interface{}{
		"total_packets": d.totalPackets,
		"unique_ips":    len(d.packetsByIP),
		"detections":    len(d.detectedIPs),
	}
}
