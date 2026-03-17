package capture

import (
	"akrion/internal/detection"
	"akrion/pkg/models"
	"akrion/pkg/repository"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const (
	SnapLen = 96
)

// PacketCapture захватывает сетевые пакеты и передаёт их в детектор
type PacketCapture struct {
	handle      *pcap.Handle
	detector    *detection.PortScanDetector
	repo        *repository.Repository
	stopChan    chan struct{}
	batchChan   chan *models.TrafficStat
}

// NewPacketCapture создаёт захватчик пакетов
func NewPacketCapture(interfaceName string, repo *repository.Repository) (*PacketCapture, error) {
	var localIP net.IP
	var captureIface string
	var ourIPs []net.IP

	if interfaceName == "any" {
		captureIface = "any"
		ifaces, err := net.Interfaces()
		if err != nil {
			return nil, fmt.Errorf("не удалось получить список интерфейсов: %v", err)
		}
		for _, iface := range ifaces {
			addrs, _ := iface.Addrs()
			for _, addr := range addrs {
				if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
					ourIPs = append(ourIPs, ipnet.IP)
				}
			}
		}
		if len(ourIPs) == 0 {
			return nil, fmt.Errorf("не найден IPv4 адрес для фильтра (any)")
		}
		localIP = ourIPs[0]
		log.Printf("Режим 'any': захват на всех интерфейсах, %d IP для фильтра", len(ourIPs))
	} else {
		iface, err := net.InterfaceByName(interfaceName)
		if err != nil {
			return nil, fmt.Errorf("не удалось найти интерфейс %s: %v", interfaceName, err)
		}
		addrs, err := iface.Addrs()
		if err != nil || len(addrs) == 0 {
			return nil, fmt.Errorf("не удалось получить IP адрес интерфейса %s", interfaceName)
		}
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
				localIP = ipnet.IP
				break
			}
		}
		if localIP == nil {
			return nil, fmt.Errorf("не найден IPv4 адрес для интерфейса %s", interfaceName)
		}
		ourIPs = []net.IP{localIP}
		captureIface = interfaceName
	}

	handle, err := pcap.OpenLive(captureIface, SnapLen, true, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("не удалось открыть интерфейс %s: %v", captureIface, err)
	}

	var filter string
	if len(ourIPs) > 1 {
		parts := make([]string, len(ourIPs))
		for i, ip := range ourIPs {
			parts[i] = fmt.Sprintf("dst host %s", ip.String())
		}
		filter = fmt.Sprintf("tcp[tcpflags] == 0x02 and (%s)", strings.Join(parts, " or "))
	} else {
		filter = fmt.Sprintf("tcp[tcpflags] == 0x02 and dst host %s", localIP.String())
	}
	log.Printf("BPF фильтр: %s", filter)
	if err := handle.SetBPFFilter(filter); err != nil {
		handle.Close()
		return nil, fmt.Errorf("не удалось установить BPF фильтр: %v", err)
	}

	detector := detection.NewPortScanDetector(repo, localIP.String())

	pc := &PacketCapture{
		handle:    handle,
		detector:  detector,
		repo:      repo,
		stopChan:  make(chan struct{}),
		batchChan: make(chan *models.TrafficStat, 1000),
	}

	log.Printf("Захват пакетов инициализирован: интерфейс %s, IP: %s", captureIface, localIP.String())
	return pc, nil
}

// Start начинает захват пакетов
func (pc *PacketCapture) Start() error {
	go pc.batchProcessor()

	packetSource := gopacket.NewPacketSource(pc.handle, pc.handle.LinkType())
	log.Println("Начало захвата пакетов...")

	for {
		select {
		case <-pc.stopChan:
			return nil
		case pkt := <-packetSource.Packets():
			pc.processPacket(pkt)
		}
	}
}

// Stop останавливает захват
func (pc *PacketCapture) Stop() {
	close(pc.stopChan)
	pc.handle.Close()
	log.Println("Захват пакетов остановлен")
}

// GetStats возвращает статистику (делегирует в детектор)
func (pc *PacketCapture) GetStats() map[string]interface{} {
	return pc.detector.GetStats()
}

func (pc *PacketCapture) processPacket(packet gopacket.Packet) {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return
	}

	ip, _ := ipLayer.(*layers.IPv4)
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return
	}

	tcp, _ := tcpLayer.(*layers.TCP)
	srcIP := ip.SrcIP.String()
	dstIP := ip.DstIP.String()
	srcPort := int(tcp.SrcPort)
	dstPort := int(tcp.DstPort)

	pc.detector.OnPacket(srcIP, dstIP, srcPort, dstPort)

	stat := &models.TrafficStat{
		Timestamp:   time.Now(),
		Protocol:    "TCP",
		SrcIP:       srcIP,
		DstIP:       dstIP,
		SrcPort:     srcPort,
		DstPort:     dstPort,
		PacketCount: 1,
	}

	select {
	case pc.batchChan <- stat:
	default:
		log.Println("Предупреждение: канал статистики переполнен")
	}

	log.Printf("[+] %s:%d -> %s:%d", srcIP, srcPort, dstIP, dstPort)
}

func (pc *PacketCapture) batchProcessor() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	batch := make([]*models.TrafficStat, 0, 100)

	for {
		select {
		case <-pc.stopChan:
			if len(batch) > 0 {
				pc.repo.SaveTrafficStatsBatch(batch)
			}
			return
		case stat := <-pc.batchChan:
			batch = append(batch, stat)
			if len(batch) >= 100 {
				pc.repo.SaveTrafficStatsBatch(batch)
				batch = batch[:0]
			}
		case <-ticker.C:
			if len(batch) > 0 {
				pc.repo.SaveTrafficStatsBatch(batch)
				batch = batch[:0]
			}
		}
	}
}
