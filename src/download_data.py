# src/real_data_connectors.py
import psutil
import socket
import platform
from datetime import datetime
import pandas as pd

class RealTimeDataCollector:
    def collect_system_metrics(self):
        """Collect real system metrics"""
        return {
            'timestamp': datetime.now(),
            'cpu_percent': psutil.cpu_percent(),
            'memory_percent': psutil.virtual_memory().percent,
            'disk_usage': psutil.disk_usage('/').percent,
            'network_io': psutil.net_io_counters(),
            'logged_in_users': len(psutil.users()),
            'boot_time': psutil.boot_time()
        }
    
    def collect_network_data(self):
        """Collect network connection data"""
        connections = []
        for conn in psutil.net_connections():
            if conn.status == 'ESTABLISHED':
                connections.append({
                    'local_address': conn.laddr,
                    'remote_address': conn.raddr,
                    'status': conn.status,
                    'pid': conn.pid
                })
        return connections

# Real-time data collection
collector = RealTimeDataCollector()
metrics = collector.collect_system_metrics()
network_data = collector.collect_network_data()