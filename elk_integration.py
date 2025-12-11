# elk_integration.py - FIXED VERSION
import json
from datetime import datetime, timedelta
import logging
import warnings

# Suppress warnings
warnings.filterwarnings("ignore")

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ELKManager:
    def __init__(self, host='localhost', port=9200, username='elastic', password=''):
        """
        Initialize ELK manager with connection parameters
        """
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.es = None
        self.connected = False
        
        # Try to import Elasticsearch
        try:
            from elasticsearch import Elasticsearch
            self.Elasticsearch = Elasticsearch
            
            # Try to connect
            self.connect()
        except ImportError:
            logger.warning("Elasticsearch module not installed. Install with: pip install elasticsearch==8.11.0")
            self.Elasticsearch = None
        except Exception as e:
            logger.error(f"Error initializing ELK: {e}")
    
    def connect(self):
        """Establish connection to Elasticsearch"""
        if not self.Elasticsearch:
            return False
        
        try:
            # Try with basic connection first
            self.es = self.Elasticsearch(
                [f'http://{self.host}:{self.port}'],
                basic_auth=(self.username, self.password) if self.password else None,
                request_timeout=30,
                max_retries=3,
                retry_on_timeout=True,
                verify_certs=False
            )
            
            # Test connection
            if self.es.ping():
                self.connected = True
                logger.info(f"✅ Connected to Elasticsearch at {self.host}:{self.port}")
                return True
            else:
                logger.error("❌ Elasticsearch ping failed")
                self.connected = False
                return False
                
        except Exception as e:
            logger.error(f"❌ Cannot connect to Elasticsearch: {e}")
            
            # Try without authentication as fallback
            try:
                self.es = self.Elasticsearch(
                    [f'http://{self.host}:{self.port}'],
                    request_timeout=10,
                    verify_certs=False
                )
                
                if self.es.ping():
                    self.connected = True
                    logger.info(f"✅ Connected to Elasticsearch (no auth) at {self.host}:{self.port}")
                    return True
            except Exception as e2:
                logger.error(f"❌ Fallback connection also failed: {e2}")
            
            self.connected = False
            return False
    
    def check_status(self):
        """Check ELK stack status"""
        status = {
            'elasticsearch': False,
            'kibana': False,
            'indices': [],
            'cluster_name': 'Unknown',
            'health': 'unknown'
        }
        
        if not self.connected:
            if self.Elasticsearch:
                # Try to reconnect
                self.connect()
            else:
                return status
        
        try:
            # Get cluster info
            info = self.es.info()
            status['elasticsearch'] = True
            status['cluster_name'] = info.get('cluster_name', 'Unknown')
            
            # Get cluster health
            health = self.es.cluster.health()
            status['health'] = health.get('status', 'unknown')
            
            # Get indices
            try:
                indices = self.es.cat.indices(format='json', h='index')
                status['indices'] = [idx['index'] for idx in indices]
            except:
                status['indices'] = []
            
            # Check Kibana (basic check)
            try:
                import requests
                kibana_response = requests.get(f'http://{self.host}:5601', timeout=5)
                status['kibana'] = kibana_response.status_code == 200
            except:
                status['kibana'] = False
            
            return status
            
        except Exception as e:
            logger.error(f"Error checking ELK status: {e}")
            return status
    
    def search_threats(self, query="*", size=50):
        """Search for threats in Elasticsearch"""
        if not self.connected:
            logger.warning("Not connected to Elasticsearch")
            return []
        
        try:
            # Try different index names
            indices_to_try = ['threats', 'threat-*', 'log*', 'security-*', '*']
            
            for index in indices_to_try:
                try:
                    response = self.es.search(
                        index=index,
                        body={
                            "query": {
                                "query_string": {
                                    "query": query
                                }
                            },
                            "size": size
                        }
                    )
                    
                    if response['hits']['hits']:
                        threats = []
                        for hit in response['hits']['hits']:
                            threat_data = hit['_source']
                            threat_data['_id'] = hit['_id']
                            threats.append(threat_data)
                        
                        logger.info(f"Found {len(threats)} threats in index '{index}'")
                        return threats
                        
                except Exception as e:
                    continue
            
            logger.info("No threats found in any index")
            return []
            
        except Exception as e:
            logger.error(f"Error searching threats: {e}")
            return []
    
    def search_index(self, index="*", query=None, size=50):
        """Generic search in any index"""
        if not self.connected:
            return {'hits': {'hits': [], 'total': {'value': 0}}}
        
        try:
            if query is None:
                query = {"query": {"match_all": {}}}
            
            response = self.es.search(
                index=index,
                body=query,
                size=size
            )
            return response
            
        except Exception as e:
            logger.error(f"Error searching index: {e}")
            return {'hits': {'hits': [], 'total': {'value': 0}}}
    
    def get_threat_stats(self):
        """Get threat statistics from Elasticsearch"""
        if not self.connected:
            return {}
        
        try:
            # Aggregation query for threat stats
            query = {
                "size": 0,
                "aggs": {
                    "severity_distribution": {
                        "terms": {
                            "field": "severity.keyword",
                            "size": 10
                        }
                    },
                    "recent_threats": {
                        "date_histogram": {
                            "field": "timestamp",
                            "calendar_interval": "hour",
                            "min_doc_count": 0
                        }
                    }
                }
            }
            
            response = self.es.search(index="threat*", body=query)
            return response.get('aggregations', {})
            
        except Exception as e:
            logger.error(f"Error getting threat stats: {e}")
            return {}
    
    def create_sample_data(self):
        """Create sample threat data for testing"""
        if not self.connected:
            logger.warning("Cannot create sample data - not connected")
            return False
        
        try:
            # Create sample threats
            sample_threats = [
                {
                    "threat_id": f"THREAT-{i:04d}",
                    "threat_type": "Data Exfiltration",
                    "severity": "High",
                    "user_id": f"USER-{1000 + i}",
                    "timestamp": (datetime.now() - timedelta(hours=i)).isoformat(),
                    "description": f"Sample threat {i} - Unusual data access pattern detected",
                    "department": "Engineering",
                    "risk_score": 75 + i
                }
                for i in range(10)
            ]
            
            # Index the sample data
            for i, threat in enumerate(sample_threats):
                self.es.index(
                    index="threats",
                    id=threat["threat_id"],
                    document=threat
                )
            
            logger.info(f"Created {len(sample_threats)} sample threats")
            return True
            
        except Exception as e:
            logger.error(f"Error creating sample data: {e}")
            return False
    
    def check_and_create_index(self):
        """Check if index exists, create if not"""
        if not self.connected:
            return False
        
        try:
            # Check if threats index exists
            if not self.es.indices.exists(index="threats"):
                # Create index with mapping
                self.es.indices.create(
                    index="threats",
                    body={
                        "settings": {
                            "number_of_shards": 1,
                            "number_of_replicas": 0
                        },
                        "mappings": {
                            "properties": {
                                "threat_id": {"type": "keyword"},
                                "threat_type": {"type": "keyword"},
                                "severity": {"type": "keyword"},
                                "user_id": {"type": "keyword"},
                                "timestamp": {"type": "date"},
                                "description": {"type": "text"},
                                "department": {"type": "keyword"},
                                "risk_score": {"type": "integer"}
                            }
                        }
                    }
                )
                logger.info("Created 'threats' index")
                return True
            else:
                logger.info("'threats' index already exists")
                return True
                
        except Exception as e:
            logger.error(f"Error checking/creating index: {e}")
            return False

# Mock ELKManager for when Elasticsearch is not available
class MockELKManager:
    def __init__(self, *args, **kwargs):
        self.connected = False
        self.mock_data = []
    
    def connect(self):
        return False
    
    def check_status(self):
        return {
            'elasticsearch': False,
            'kibana': False,
            'indices': [],
            'cluster_name': 'Mock Cluster',
            'health': 'red'
        }
    
    def search_threats(self, *args, **kwargs):
        return []
    
    def search_index(self, *args, **kwargs):
        return {'hits': {'hits': [], 'total': {'value': 0}}}
    
    def get_threat_stats(self):
        return {}
    
    def create_sample_data(self):
        return False
    
    def check_and_create_index(self):
        return False

# Export both classes
__all__ = ['ELKManager', 'MockELKManager']