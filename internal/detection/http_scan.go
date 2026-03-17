package detection

import (
	"akrion/pkg/models"
	"akrion/pkg/repository"
	"log"
	"regexp"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// Паттерны nmap и сканеров в HTTP-запросах
var httpScanPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)nmap`),
	regexp.MustCompile(`(?i)nmaplowercheck\d+`),
	regexp.MustCompile(`(?i)nmap.*check`),
	regexp.MustCompile(`(?i)nikto`),
	regexp.MustCompile(`(?i)sqlmap`),
	regexp.MustCompile(`(?i)dirbuster`),
	regexp.MustCompile(`(?i)gobuster`),
	regexp.MustCompile(`(?i)ffuf`),
}

type httpScanDetector struct {
	repo       *repository.Repository
	alertedIPs map[string]time.Time
	mu         sync.RWMutex
	cooldown   time.Duration
}

// HttpScan создаёт HTTP middleware для обнаружения запросов сканеров
func HttpScan(repo *repository.Repository) gin.HandlerFunc {
	d := &httpScanDetector{
		repo:       repo,
		alertedIPs: make(map[string]time.Time),
		cooldown:   5 * time.Minute,
	}
	return d.handle
}

func (d *httpScanDetector) handle(c *gin.Context) {
	path := c.Request.URL.Path
	clientIP := c.ClientIP()

	for _, pattern := range httpScanPatterns {
		if pattern.MatchString(path) {
			d.mu.Lock()
			lastAlert := d.alertedIPs[clientIP]
			if time.Since(lastAlert) < d.cooldown {
				d.mu.Unlock()
				break
			}
			d.alertedIPs[clientIP] = time.Now()
			d.mu.Unlock()

			detection := &models.Detection{
				Timestamp:   time.Now(),
				Type:        "nmap_http_scan",
				SrcIP:       clientIP,
				DstIP:       "",
				Description: "Обнаружен HTTP-запрос сканера (nmap/nikto/sqlmap): " + path,
				Severity:    "high",
			}
			go func() {
				if err := d.repo.SaveDetection(detection); err != nil {
					log.Printf("Ошибка сохранения обнаружения nmap: %v", err)
				} else {
					log.Printf("[!] ОБНАРУЖЕНО: HTTP-скан от %s: %s", clientIP, path)
				}
			}()
			break
		}
	}

	c.Next()
}
