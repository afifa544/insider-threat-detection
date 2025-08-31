# src/test_lightweight.py
import subprocess
import sys

def test_lightweight_pipeline():
    """Test the lightweight pipeline"""
    commands = [
        "python src/download_data.py",
        "python src/preprocess_lightweight.py", 
        "python src/train_baseline_lightweight.py",
        "python src/predict_local.py"
    ]
    
    for cmd in commands:
        print(f"Running: {cmd}")
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        if result.returncode != 0:
            print(f"Error running {cmd}:")
            print(result.stderr)
            return False
        else:
            print("✓ Success")
    
    print("All tests passed!")
    return True

if __name__ == "__main__":
    success = test_lightweight_pipeline()
    sys.exit(0 if success else 1)