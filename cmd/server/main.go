package main

import (
	"akrion/internal/capture"
	"akrion/internal/config"
	"akrion/internal/server"
	"akrion/pkg/monitor"
	"akrion/pkg/repository"
	"akrion/pkg/websocket"
	"fmt"
	"log"
	"time"
)

const banner = `
                 ...                                                                      
       .     :=++==+                                                                      
   .+++-- :+##=:...-.:                                                                    
    -*******=..::::- .                                                                    
    ::****+:.......:::                       ..                 ...                       
    :-***+::::::::-:  .           ......     ..                                           
    .***=.........-:.             ..  ...    ..   ...   ......  ...   ........   ........ 
    =*+=:........--. :           ...  ...    ......    ...      ...  ...   ....  ...   ...
    +=:..:::::::----+=:         ..........   ......    ...      ...  ...    ...  ...   ...
  .=:-=-::::...--==:.==-        ...    ...   ..  ....  ...      ...   ........   ...   ...
 ==..+*-::...:.*##.:--:-:                                                                 
-:  ..--:....:+###    .-=                                                                 
       :+=.::.:-+#+:                                                                      
        --     . -+*#+:                                                                   
                      .                                                                   
`

func main() {
	fmt.Print(banner)

	cfg := config.Parse()
	if err := cfg.Validate(); err != nil {
		log.Fatal(err)
	}

	repo, err := repository.NewRepository(cfg.DBPath)
	if err != nil {
		log.Fatalf("Ошибка инициализации БД: %v", err)
	}
	log.Println("База данных инициализирована")

	packetCapture, err := capture.NewPacketCapture(cfg.Interface, repo)
	if err != nil {
		log.Fatalf("Ошибка инициализации захвата пакетов: %v", err)
	}

	go func() {
		if err := packetCapture.Start(); err != nil {
			log.Fatalf("Ошибка запуска захвата пакетов: %v", err)
		}
	}()

	sysMonitor := monitor.NewSystemMonitor(repo, 5*time.Second)
	go sysMonitor.Start()

	hub := websocket.NewHub()
	go hub.Run()

	deps := &server.Dependencies{
		Repo:    repo,
		Capture: packetCapture,
		SysMonitor: sysMonitor,
		Hub:        hub,
	}

	server.StartBroadcast(deps)

	r := server.New(deps)
	log.Printf("Веб-сервер запущен на порту %s", cfg.Port)
	log.Printf("Откройте http://localhost:%s в браузере", cfg.Port)
	if err := r.Run(":" + cfg.Port); err != nil {
		log.Fatalf("Ошибка запуска веб-сервера: %v", err)
	}
}
