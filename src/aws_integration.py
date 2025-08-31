# src/aws_integration.py
import boto3
from botocore.exceptions import ClientError

class AWSCloudWatchLogger:
    def __init__(self):
        self.client = boto3.client('cloudwatch', region_name='us-east-1')
    
    def log_anomaly(self, user_data, score, reason):
        """Log anomalies to AWS CloudWatch"""
        try:
            response = self.client.put_metric_data(
                Namespace='InsiderThreat',
                MetricData=[{
                    'MetricName': 'AnomalyScore',
                    'Dimensions': [{'Name': 'User', 'Value': user_data['user']}],
                    'Value': score,
                    'Unit': 'Count'
                }]
            )
            return True
        except ClientError as e:
            print(f"AWS Error: {e}")
            return False

class S3DataBackup:
    def __init__(self):
        self.s3 = boto3.client('s3')
    
    def backup_to_s3(self, file_path, bucket_name):
        """Backup data to S3"""
        try:
            self.s3.upload_file(file_path, bucket_name, f"backups/{file_path}")
            return True
        except ClientError as e:
            print(f"S3 Upload Error: {e}")
            return False