// WebSocket подключение
let ws = null;
let reconnectAttempts = 0;
const maxReconnectAttempts = 5;

function connectWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws`;
    
    ws = new WebSocket(wsUrl);

    ws.onopen = () => {
        console.log('WebSocket подключен');
        reconnectAttempts = 0;
    };

    ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        if (data.type === 'update') {
            updateDashboard(data.data);
        }
    };

    ws.onerror = (error) => {
        console.error('WebSocket ошибка:', error);
    };

    ws.onclose = () => {
        console.log('WebSocket отключен');
        if (reconnectAttempts < maxReconnectAttempts) {
            reconnectAttempts++;
            setTimeout(connectWebSocket, 3000);
        }
    };
}

// Управление вкладками
document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        const tabName = btn.dataset.tab;
        
        // Убираем активный класс со всех кнопок и контента
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
        
        // Добавляем активный класс к выбранной кнопке и контенту
        btn.classList.add('active');
        document.getElementById(tabName).classList.add('active');
        
        // Загружаем данные для активной вкладки
        loadTabData(tabName);
    });
});

// Загрузка данных для вкладки
function loadTabData(tabName) {
    switch(tabName) {
        case 'home':
            loadTrafficStats();
            loadTraffic();
            break;
        case 'detect':
            loadDetections();
            break;
        case 'honeypot':
            loadHoneypot();
            break;
        case 'system':
            loadSystemMetrics();
            break;
    }
}

// Обновление дашборда через WebSocket
function updateDashboard(data) {
    if (data.packet_stats) {
        updatePacketStats(data.packet_stats);
    }
    
    if (data.system) {
        updateSystemMetrics(data.system);
    }
    
    if (data.summary) {
        updateSummary(data.summary);
    }
}

// Обновление статистики пакетов
function updatePacketStats(stats) {
    if (!stats) return;
    const totalEl = document.getElementById('total-packets');
    const uniqueEl = document.getElementById('unique-ips');
    const detectionsEl = document.getElementById('detections');
    if (totalEl && stats.total_packets !== undefined) {
        totalEl.textContent = formatNumber(stats.total_packets);
    }
    if (uniqueEl && stats.unique_ips !== undefined) {
        uniqueEl.textContent = formatNumber(stats.unique_ips);
    }
    if (detectionsEl && (stats.detections !== undefined || stats.total_detections !== undefined)) {
        const count = stats.detections !== undefined ? stats.detections : (stats.total_detections || 0);
        detectionsEl.textContent = formatNumber(count);
    }
}

// Обновление системных метрик
function updateSystemMetrics(metrics) {
    if (metrics.cpu_percent !== undefined) {
        const cpuPercent = Math.round(metrics.cpu_percent);
        document.getElementById('cpu-progress').style.width = cpuPercent + '%';
        document.getElementById('cpu-text').textContent = cpuPercent + '%';
    }
    
    if (metrics.ram_percent !== undefined) {
        const ramPercent = Math.round(metrics.ram_percent);
        document.getElementById('ram-progress').style.width = ramPercent + '%';
        document.getElementById('ram-text').textContent = ramPercent + '%';
    }
    
    if (metrics.ram_used !== undefined) {
        document.getElementById('ram-used').textContent = formatBytes(metrics.ram_used);
    }
    
    if (metrics.ram_free !== undefined) {
        document.getElementById('ram-free').textContent = formatBytes(metrics.ram_free);
    }
    
    if (metrics.ram_total !== undefined) {
        document.getElementById('ram-total').textContent = formatBytes(metrics.ram_total);
    }
}

// Обновление сводки (данные из БД)
function updateSummary(summary) {
    if (!summary) return;
    const totalEl = document.getElementById('total-packets');
    const uniqueEl = document.getElementById('unique-ips');
    const detectionsEl = document.getElementById('detections');
    if (totalEl && summary.total_packets !== undefined) {
        totalEl.textContent = formatNumber(summary.total_packets);
    }
    if (uniqueEl && summary.unique_ips !== undefined) {
        uniqueEl.textContent = formatNumber(summary.unique_ips);
    }
    if (detectionsEl && summary.total_detections !== undefined) {
        detectionsEl.textContent = formatNumber(summary.total_detections);
    }
}

// Загрузка статистики трафика (объединяем данные из API и БД)
async function loadTrafficStats() {
    try {
        // Загружаем оба источника: реальное время (analyzer) и БД
        const [statsRes, summaryRes] = await Promise.all([
            fetch('/api/stats'),
            fetch('/api/summary')
        ]);
        
        const stats = statsRes.ok ? await statsRes.json() : null;
        const summary = summaryRes.ok ? await summaryRes.json() : null;
        
        // Приоритет: берём максимум из обоих источников для отображения
        const merged = {
            total_packets: Math.max(stats?.total_packets || 0, summary?.total_packets || 0),
            unique_ips: Math.max(stats?.unique_ips || 0, summary?.unique_ips || 0),
            detections: Math.max(stats?.detections || 0, summary?.total_detections || 0)
        };
        updatePacketStats(merged);
    } catch (error) {
        console.error('Ошибка загрузки статистики:', error);
    }
}

// Загрузка трафика
async function loadTraffic() {
    try {
        const response = await fetch('/api/traffic');
        const data = await response.json();
        renderTrafficTable(data);
    } catch (error) {
        console.error('Ошибка загрузки трафика:', error);
    }
}

// Загрузка обнаружений
async function loadDetections() {
    try {
        const response = await fetch('/api/detections');
        const data = await response.json();
        renderDetectionsTable(data);
    } catch (error) {
        console.error('Ошибка загрузки обнаружений:', error);
    }
}

// Загрузка активности honeypot
async function loadHoneypot() {
    try {
        const response = await fetch('/api/honeypot');
        const data = await response.json();
        renderHoneypotTable(data);
    } catch (error) {
        console.error('Ошибка загрузки honeypot:', error);
    }
}

// Загрузка системных метрик
async function loadSystemMetrics() {
    try {
        // Текущие метрики
        const currentResponse = await fetch('/api/system/current');
        const currentData = await currentResponse.json();
        updateSystemMetrics(currentData);
    } catch (error) {
        console.error('Ошибка загрузки системных метрик:', error);
    }
}

// Рендеринг таблицы трафика
function renderTrafficTable(data) {
    const tbody = document.getElementById('traffic-tbody');
    if (!tbody) return;
    tbody.innerHTML = '';
    
    data = Array.isArray(data) ? data : [];
    data.slice(0, 50).forEach(item => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${formatTime(item.timestamp)}</td>
            <td>${item.src_ip}</td>
            <td>${item.src_port}</td>
            <td>${item.dst_ip}</td>
            <td>${item.dst_port}</td>
            <td>${item.protocol}</td>
        `;
        tbody.appendChild(row);
    });
}

// Рендеринг таблицы обнаружений
function renderDetectionsTable(data) {
    const tbody = document.getElementById('detections-tbody');
    tbody.innerHTML = '';
    
    data.forEach(item => {
        const row = document.createElement('tr');
        const severityClass = `severity-${item.severity}`;
        row.innerHTML = `
            <td>${formatTime(item.timestamp)}</td>
            <td>${item.type}</td>
            <td>${item.src_ip}</td>
            <td>${item.dst_ip}</td>
            <td>${item.description}</td>
            <td class="${severityClass}">${item.severity}</td>
        `;
        tbody.appendChild(row);
    });
}

// Рендеринг таблицы honeypot
function renderHoneypotTable(data) {
    const tbody = document.getElementById('honeypot-tbody');
    tbody.innerHTML = '';
    
    data.forEach(item => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${formatTime(item.timestamp)}</td>
            <td>${item.src_ip}</td>
            <td>${item.dst_port}</td>
            <td>${item.protocol}</td>
            <td>${item.action}</td>
        `;
        tbody.appendChild(row);
    });
}


// Форматирование времени
function formatTime(timestamp) {
    const date = new Date(timestamp);
    return date.toLocaleString('ru-RU');
}

// Форматирование чисел
function formatNumber(num) {
    return new Intl.NumberFormat('ru-RU').format(num);
}

// Форматирование байтов
function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}

// Инициализация при загрузке страницы
document.addEventListener('DOMContentLoaded', () => {
    connectWebSocket();
    loadTabData('home');
    
    // Обновление данных каждые 5 секунд
    setInterval(() => {
        const activeTab = document.querySelector('.tab-content.active').id;
        loadTabData(activeTab);
    }, 5000);
});
