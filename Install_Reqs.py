import subprocess
import sys

def install_packages():
    try:
        with open('requirements.txt', 'r') as file:
            packages = file.readlines()
            packages = [package.strip() for package in packages]
            
            for package in packages:
                subprocess.run(['pip', 'install', package])
                print(f'Successfully installed {package}')
                
    except FileNotFoundError:
        print("requirements.txt file not found.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to install {e.cmd}. Error: {e.output}")

if __name__ == "__main__":
    install_packages()
