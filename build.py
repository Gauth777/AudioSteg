import os
import subprocess
import sys
import shutil

def main():
    """Build the AudioSteg standalone executable using PyInstaller."""
    print("="*50)
    print("Building AudioSteg Standalone Executable")
    print("="*50)

    # Ensure pyinstaller is installed
    try:
        import PyInstaller
    except ImportError:
        print("PyInstaller not found. Installing from requirements...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])

    # Clean previous builds
    for dir_name in ["build", "dist"]:
        if os.path.exists(dir_name):
            print(f"Cleaning {dir_name} directory...")
            shutil.rmtree(dir_name)

    # Determine the path separator for PyInstaller --add-data
    # Windows uses ';', Linux/macOS uses ':'
    sep = os.pathsep

    # Define PyInstaller arguments
    # We do NOT use --windowed so that the user has a terminal to view logs 
    # and a clear way to shut down the Flask server by closing the terminal.
    args = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm",
        "--onefile",
        "--name", "AudioSteg",
        "--add-data", f"templates{sep}templates",
        "--add-data", f"static{sep}static",
        "--clean",
        "app.py"
    ]

    print(f"Running PyInstaller with arguments: {' '.join(args)}")
    try:
        subprocess.check_call(args)
        print("\n" + "="*50)
        print("Build Complete!")
        print("The standalone executable 'AudioSteg.exe' can be found in the 'dist' directory.")
        print("="*50)
    except subprocess.CalledProcessError as e:
        print(f"Build failed with error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
