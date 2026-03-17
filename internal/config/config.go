package config

import (
	"flag"
	"os"
)

// Config содержит настройки приложения
type Config struct {
	Interface   string
	DBPath      string
	Port        string
}

// Parse парсит флаги и возвращает конфигурацию
func Parse() *Config {
	cfg := &Config{}
	flag.StringVar(&cfg.Interface, "interface", "", "Имя сетевого интерфейса (обязательно)")
	flag.StringVar(&cfg.DBPath, "db", "akrion.db", "Путь к файлу базы данных SQLite")
	flag.StringVar(&cfg.Port, "port", "1337", "Порт для веб-сервера")
	flag.Parse()
	return cfg
}

// Validate проверяет конфигурацию
func (c *Config) Validate() error {
	if c.Interface == "" {
		return ErrInterfaceRequired
	}
	if os.Geteuid() != 0 {
		return ErrRootRequired
	}
	return nil
}
