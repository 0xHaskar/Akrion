package server

import (
	"akrion/internal/capture"
	"akrion/pkg/monitor"
	"akrion/pkg/repository"
	"net/http"

	"github.com/gin-gonic/gin"
)

// handlers содержит HTTP-обработчики API
var handlers = &apiHandlers{}

type apiHandlers struct{}

func (h *apiHandlers) Traffic(repo *repository.Repository) gin.HandlerFunc {
	return func(c *gin.Context) {
		stats, err := repo.GetRecentTrafficStats(100)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, stats)
	}
}

func (h *apiHandlers) Detections(repo *repository.Repository) gin.HandlerFunc {
	return func(c *gin.Context) {
		detections, err := repo.GetRecentDetections(100)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, detections)
	}
}

func (h *apiHandlers) Honeypot(repo *repository.Repository) gin.HandlerFunc {
	return func(c *gin.Context) {
		activities, err := repo.GetRecentHoneypotActivity(100)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, activities)
	}
}

func (h *apiHandlers) SystemCurrent(m *monitor.SystemMonitor) gin.HandlerFunc {
	return func(c *gin.Context) {
		metrics, err := m.GetCurrentMetrics()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, metrics)
	}
}

func (h *apiHandlers) Summary(repo *repository.Repository) gin.HandlerFunc {
	return func(c *gin.Context) {
		summary, err := repo.GetTrafficSummary()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, summary)
	}
}

func (h *apiHandlers) Stats(cap *capture.PacketCapture) gin.HandlerFunc {
	return func(c *gin.Context) {
		stats := cap.GetStats()
		c.JSON(http.StatusOK, stats)
	}
}
