# run_complete.py
import subprocess
import sys
import time

def run_command(command, description):
    """Run a command and return success status"""
    print(f"\n🔧 {description}")
    print(f"   Running: {command}")
    
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            print("   ✅ Success")
            return True
        else:
            print(f"   ❌ Failed with error: {result.stderr}")
            return False
    except Exception as e:
        print(f"   ❌ Exception: {e}")
        return False

def main():
    print("🔥 Starting Complete Insider Threat Detection Pipeline")
    print("=" * 60)
    
    steps = [
        ("python src/download_data.py", "Creating synthetic data"),
        ("python src/preprocess_lightweight.py", "Preprocessing data"),
        ("python src/train_baseline_lightweight.py", "Training machine learning model"),
        ("python src/predict_local.py", "Generating predictions")
    ]
    
    for command, description in steps:
        if not run_command(command, description):
            print(f"\n❌ Pipeline failed at: {description}")
            print("Please check the error above and try again.")
            sys.exit(1)
        time.sleep(1)  # Brief pause between steps
    
    print("\n🎉 Pipeline completed successfully!")
    print("\nTo view the dashboard, run:")
    print("   streamlit run dashboard/lightweight_app.py")
    
    # Ask if user wants to start the dashboard
    response = input("\nWould you like to start the dashboard now? (y/n): ")
    if response.lower() in ['y', 'yes']:
        print("Starting dashboard...")
        subprocess.run("streamlit run dashboard/lightweight_app.py", shell=True)

if __name__ == "__main__":
    main()