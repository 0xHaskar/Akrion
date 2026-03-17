package server

import (
	"akrion/internal/capture"
	"akrion/internal/detection"
	"akrion/pkg/monitor"
	"akrion/pkg/repository"
	"akrion/pkg/websocket"
	"net/http"

	"github.com/gin-gonic/gin"
	ws "github.com/gorilla/websocket"
)

// Dependencies содержит зависимости сервера
type Dependencies struct {
	Repo       *repository.Repository
	Capture    *capture.PacketCapture
	SysMonitor *monitor.SystemMonitor
	Hub        *websocket.Hub
}

// New создаёт и настраивает Gin роутер
func New(deps *Dependencies) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()

	// Middleware
	r.Use(detection.HttpScan(deps.Repo))

	// Статика и шаблоны
	r.Static("/static", "./web/static")
	r.LoadHTMLGlob("web/templates/*")

	// Роуты
	setupRoutes(r, deps)

	return r
}

func setupRoutes(r *gin.Engine, deps *Dependencies) {
	r.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", nil)
	})

	upgrader := ws.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	r.GET("/ws", func(c *gin.Context) {
		conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
		if err != nil {
			return
		}
		client := websocket.NewClient(deps.Hub, conn)
		deps.Hub.Register <- client
		go client.WritePump()
		go client.ReadPump()
	})

	api := r.Group("/api")
	{
		api.GET("/traffic", handlers.Traffic(deps.Repo))
		api.GET("/detections", handlers.Detections(deps.Repo))
		api.GET("/honeypot", handlers.Honeypot(deps.Repo))
		api.GET("/system/current", handlers.SystemCurrent(deps.SysMonitor))
		api.GET("/summary", handlers.Summary(deps.Repo))
		api.GET("/stats", handlers.Stats(deps.Capture))
	}
}
