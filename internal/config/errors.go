package config

import "errors"

var (
	ErrInterfaceRequired = errors.New("необходимо указать имя сетевого интерфейса через флаг -interface")
	ErrRootRequired      = errors.New("программа должна запускаться с правами root для захвата пакетов")
)
