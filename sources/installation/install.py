import subprocess
import sys

# List of packages to install
packages = [
    "flask",
    "beautifulsoup4",
    "pycryptodomex",
    "notify2",
    "pyinotify",
    "psutil"
]

# Function to install a package
def install_package(package):
    subprocess.check_call([sys.executable, "-m", "pip", "install", package])

# Install each package from the list
for package in packages:
    try:
        print(f"Installing {package}...")
        install_package(package)
        print(f"{package} installed successfully.")
    except subprocess.CalledProcessError:
        print(f"Failed to install {package}. Please check your environment or package name.")
