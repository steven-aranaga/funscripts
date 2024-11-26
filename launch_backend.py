#!/usr/bin/env python3
import os
import sys
import time
import signal
import subprocess
import logging
import logging.handlers
from typing import Dict, List, Set
from pathlib import Path
from dataclasses import dataclass
import hashlib
from threading import Thread, Event, Lock
from queue import Queue, Empty
import json
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import psutil

@dataclass
class ServiceConfig:
    name: str
    directory: Path
    script: str
    env_file: Path
    log_file: Path
    restart_delay: int = 5
    max_restarts: int = 5
    check_interval: int = 30
    file_patterns: List[str] = None

    def __post_init__(self):
        if self.file_patterns is None:
            self.file_patterns = ['*.py', '*.txt', '*.csv', 'requirements.txt']

class State:
    is_shutting_down: bool = False
    service_lock: Lock = Lock()

class ServiceProcess:
    def __init__(self, config: ServiceConfig):
        self.config = config
        self.process: subprocess.Popen = None
        self.restart_count: int = 0
        self.last_restart: float = 0
        self.file_hashes: Dict[str, str] = {}
        self.logger = logging.getLogger(f"service.{config.name}")

    def calculate_file_hashes(self) -> Dict[str, str]:
        """Calculate hashes of all monitored files in the service directory."""
        hashes = {}
        for pattern in self.config.file_patterns:
            for file_path in self.config.directory.glob(pattern):
                try:
                    if file_path.is_file():
                        with open(file_path, 'rb') as f:
                            hashes[str(file_path)] = hashlib.md5(f.read()).hexdigest()
                except Exception as e:
                    self.logger.error(f"Error hashing file {file_path}: {e}")
        return hashes

    def files_changed(self) -> bool:
        """Check if any monitored files have changed."""
        new_hashes = self.calculate_file_hashes()
        if new_hashes != self.file_hashes:
            self.logger.info("File changes detected")
            self.file_hashes = new_hashes
            return True
        return False

    def start(self) -> bool:
        """Start the service process using the virtual environment if available."""
        if self.process and self.process.poll() is None:
            return True

        try:
            # Update file hashes before starting
            self.file_hashes = self.calculate_file_hashes()

            # Prepare environment
            env = os.environ.copy()
            if self.config.env_file.exists():
                with open(self.config.env_file) as f:
                    for line in f:
                        if line.strip() and not line.startswith('#'):
                            key, value = line.strip().split('=', 1)
                            env[key] = value

            # Determine Python interpreter path
            venv_paths = [
                self.config.directory / "venv",  # Check for venv in script directory
                Path("venv"),                    # Check for venv in root directory
                self.config.directory / ".venv",  # Check for .venv in script directory
                Path(".venv"),                   # Check for .venv in root directory
            ]

            python_executable = None
            for venv_path in venv_paths:
                if os.name == 'nt':  # Windows
                    python_path = venv_path / "Scripts" / "python.exe"
                else:  # Linux/Unix
                    python_path = venv_path / "bin" / "python"
                
                if python_path.exists():
                    python_executable = str(python_path)
                    # Add virtual environment's bin to PATH
                    if os.name == 'nt':
                        env["PATH"] = f"{venv_path / 'Scripts'};{env.get('PATH', '')}"
                    else:
                        env["PATH"] = f"{venv_path / 'bin'}:{env.get('PATH', '')}"
                    break

            if not python_executable:
                self.logger.warning(f"No virtual environment found for {self.config.name}, using system Python")
                python_executable = sys.executable

            # Start process with the appropriate Python interpreter
            self.process = subprocess.Popen(
                [python_executable, self.config.script],
                cwd=str(self.config.directory),
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )

            # Start log monitoring threads
            Thread(target=self._monitor_output, args=(self.process.stdout, "INFO")).start()
            Thread(target=self._monitor_output, args=(self.process.stderr, "ERROR")).start()

            self.last_restart = time.time()
            self.restart_count = 0
            self.logger.info(f"Started service {self.config.name} using Python at {python_executable}")
            return True

        except Exception as e:
            self.logger.error(f"Error starting service {self.config.name}: {e}")
            return False

    def stop(self) -> None:
        """Stop the service process."""
        if self.process and self.process.poll() is None:
            try:
                # Try graceful shutdown first
                self.process.terminate()
                try:
                    self.process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    # Force kill if graceful shutdown fails
                    self.process.kill()
                    self.process.wait()
            except Exception as e:
                self.logger.error(f"Error stopping service {self.config.name}: {e}")
            finally:
                self.process = None

    def _monitor_output(self, pipe, level: str) -> None:
        """Monitor process output and log it."""
        for line in pipe:
            self.logger.log(
                logging.INFO if level == "INFO" else logging.ERROR,
                f"{self.config.name}: {line.strip()}"
            )

class DirectoryMonitor:
    """Monitors a directory for new Python scripts and manages them as services."""
    
    def __init__(self, directory: Path, monitor):
        self.directory = directory
        self.monitor = monitor
        self.known_scripts: Set[str] = set()
        self.logger = logging.getLogger(f"directory_monitor.{directory.name}")
        self.scan_scripts()

    def scan_scripts(self) -> None:
        """Scan directory for Python scripts and add new ones as services."""
        current_scripts = set()
        for script_path in self.directory.glob("*.py"):
            if script_path.name != "service_monitor.py":  # Ignore the monitor script
                current_scripts.add(script_path.name)
                if script_path.name not in self.known_scripts:
                    self.logger.info(f"Found new script: {script_path.name}")
                    self.add_service(script_path)
        self.known_scripts = current_scripts

    def add_service(self, script_path: Path) -> None:
        """Add a new script as a service."""
        service_name = f"{self.directory.name}.{script_path.stem}"
        config = ServiceConfig(
            name=service_name,
            directory=self.directory,
            script=script_path.name,
            env_file=self.directory / ".env",
            log_file=Path("logs") / f"{service_name}.log"
        )
        self.monitor.add_service(config)

class ServiceMonitor:
    def __init__(self):
        self.setup_logging()
        self.logger = logging.getLogger("monitor")
        self.services: Dict[str, ServiceProcess] = {}
        self.directory_monitors: Dict[str, DirectoryMonitor] = {}
        self.observer = Observer()
        self.shutdown_event = Event()
        
    def add_service(self, config: ServiceConfig) -> None:
        """Add a new service to the monitor."""
        with State.service_lock:
            if config.name not in self.services:
                self.services[config.name] = ServiceProcess(config)
                if self.observer.is_alive():  # If monitor is running, start the service
                    self.services[config.name].start()

    def setup_logging(self) -> None:
        """Configure logging with rotation."""
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)

        logger = logging.getLogger()
        logger.setLevel(logging.INFO)

        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )

        # File handler with rotation
        file_handler = logging.handlers.RotatingFileHandler(
            log_dir / "service_monitor.log",
            maxBytes=10_000_000,  # 10MB
            backupCount=5
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

    def monitor_directories(self) -> None:
        """Monitor directories for new Python scripts."""
        while not self.shutdown_event.is_set():
            for dir_monitor in self.directory_monitors.values():
                dir_monitor.scan_scripts()
            time.sleep(30)  # Check for new scripts every 30 seconds

    def monitor_service(self, service: ServiceProcess) -> None:
        """Monitor and manage a service process."""
        while not self.shutdown_event.is_set():
            try:
                # Check if process is running
                if service.process is None or service.process.poll() is not None:
                    # Check if we should restart
                    if time.time() - service.last_restart > service.config.restart_delay:
                        if service.restart_count < service.config.max_restarts:
                            self.logger.info(f"Restarting service {service.config.name}")
                            service.start()
                            service.restart_count += 1
                        else:
                            self.logger.error(
                                f"Service {service.config.name} exceeded max restarts. Manual intervention required."
                            )
                            break

                # Check for file changes
                if service.files_changed():
                    self.logger.info(f"Restarting service {service.config.name} due to file changes")
                    service.stop()
                    service.start()

                time.sleep(service.config.check_interval)

            except Exception as e:
                self.logger.error(f"Error monitoring service {service.config.name}: {e}")
                time.sleep(5)

    def start(self) -> None:
        """Start the service monitor."""
        try:
            # Initialize directory monitors and setup venvs
            for dir_name in ['api', 'backend']:
                dir_path = Path(dir_name)
                if dir_path.exists() and dir_path.is_dir():
                    # Setup virtual environment if needed
                    setup_venv(dir_path, self.logger)
                    
                    self.directory_monitors[dir_name] = DirectoryMonitor(dir_path, self)
                    self.observer.schedule(
                        ServiceFileHandler(self.directory_monitors[dir_name]),
                        str(dir_path),
                        recursive=False
                    )

            # Start file system observer
            self.observer.start()

            # Start directory monitoring thread
            dir_monitor_thread = Thread(target=self.monitor_directories)
            dir_monitor_thread.start()

            # Start service monitoring threads
            monitor_threads = []
            for service in self.services.values():
                if service.start():
                    thread = Thread(
                        target=self.monitor_service,
                        args=(service,),
                        name=f"monitor_{service.config.name}"
                    )
                    thread.start()
                    monitor_threads.append(thread)

            # Wait for shutdown signal
            self.shutdown_event.wait()

            # Clean shutdown
            self.observer.stop()
            for service in self.services.values():
                service.stop()
            
            self.observer.join()
            dir_monitor_thread.join()
            for thread in monitor_threads:
                thread.join()

        except Exception as e:
            self.logger.error(f"Error in service monitor: {e}")
        finally:
            self.cleanup()

    def cleanup(self) -> None:
        """Perform cleanup operations."""
        for service in self.services.values():
            service.stop()

class ServiceFileHandler(FileSystemEventHandler):
    def __init__(self, dir_monitor: DirectoryMonitor):
        self.dir_monitor = dir_monitor

    def on_created(self, event):
        if not event.is_directory and event.src_path.endswith('.py'):
            self.dir_monitor.scan_scripts()

    def on_modified(self, event):
        if not event.is_directory:
            self.dir_monitor.scan_scripts()

def create_systemd_service():
    """Create systemd service file."""
    service_content = """[Unit]
Description=Python Services Monitor
After=network.target

[Service]
Type=simple
User={user}
WorkingDirectory={work_dir}
Environment=PYTHONUNBUFFERED=1
ExecStart={python_path} {script_path}
Restart=always
RestartSec=5
StandardOutput=append:/var/log/service_monitor.log
StandardError=append:/var/log/service_monitor.error.log

[Install]
WantedBy=multi-user.target
"""
    
    try:
        service_path = Path("/etc/systemd/system/python_services_monitor.service")
        service_content = service_content.format(
            user=os.getenv("USER"),
            work_dir=os.getcwd(),
            python_path=sys.executable,
            script_path=os.path.abspath(__file__)
        )
        
        with open(service_path, 'w') as f:
            f.write(service_content)
            
        print(f"Created systemd service file: {service_path}")
        print("To enable and start the service, run:")
        print("sudo systemctl daemon-reload")
        print("sudo systemctl enable python_services_monitor")
        print("sudo systemctl start python_services_monitor")
        
    except Exception as e:
        print(f"Error creating systemd service file: {e}")

def setup_venv(directory: Path, logger: logging.Logger) -> None:
    """Set up virtual environment if it doesn't exist and install requirements."""
    venv_path = directory / "venv"
    requirements_path = directory / "requirements.txt"
    
    try:
        if not venv_path.exists() and requirements_path.exists():
            logger.info(f"Creating virtual environment in {directory}")
            subprocess.run([sys.executable, "-m", "venv", str(venv_path)], check=True)
            
            # Determine pip path
            if os.name == 'nt':  # Windows
                pip_path = venv_path / "Scripts" / "pip"
            else:  # Linux/Unix
                pip_path = venv_path / "bin" / "pip"
            
            # Install requirements
            logger.info(f"Installing requirements for {directory}")
            subprocess.run(
                [str(pip_path), "install", "-r", str(requirements_path)],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            logger.info(f"Virtual environment setup complete for {directory}")
            
    except subprocess.CalledProcessError as e:
        logger.error(f"Error setting up virtual environment in {directory}: {e}")
        if e.stderr:
            logger.error(f"Error output: {e.stderr.decode()}")
    except Exception as e:
        logger.error(f"Unexpected error setting up virtual environment in {directory}: {e}")
        
def signal_handler(signum, frame):
    """Handle shutdown signals."""
    State.shutdown_event.set()

def main():
    # Set up signal handlers
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    # Create systemd service if requested
    if len(sys.argv) > 1 and sys.argv[1] == '--install-service':
        create_systemd_service()
        return

    # Start monitor
    monitor = ServiceMonitor()
    monitor.start()

if __name__ == "__main__":
    main()