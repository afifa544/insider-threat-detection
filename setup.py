# setup.py
import subprocess
import sys

def install_requirements():
    requirements = [
        'streamlit==1.28.1',
        'pandas==2.1.4',
        'numpy==1.24.3',
        'plotly==5.17.0',
        'requests==2.31.0',
        'elasticsearch==8.11.0',
        'fpdf2==2.7.5',
        'redis==5.0.0',
        'smtplib',
        'email-validator==2.1.0',
        'python-dotenv==1.0.0'
    ]
    
    for package in requirements:
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', package])

if __name__ == '__main__':
    install_requirements()
    print("✅ All dependencies installed successfully!")
    print("👉 Run: streamlit run enhanced_dashboard.py")