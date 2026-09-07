import os
import sys
import time
import signal
import subprocess
import logging
import urllib.request

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [Supervisor] %(message)s")
logger = logging.getLogger("service_supervisor")

def start_backend():
    logger.info("Starting FastAPI backend (Uvicorn on port 8000)...")
    proc = subprocess.Popen([
        sys.executable, "-m", "uvicorn", "app.main:app",
        "--host", "0.0.0.0",
        "--port", "8000"
    ])
    return proc

def wait_for_backend(timeout=30):
    health_url = "http://127.0.0.1:8000/api/health"
    start = time.time()
    logger.info(f"Waiting for backend health check at {health_url}...")
    while time.time() - start < timeout:
        try:
            with urllib.request.urlopen(health_url, timeout=2) as resp:
                if resp.status == 200:
                    logger.info("FastAPI backend is ONLINE and healthy! 🟢")
                    return True
        except Exception:
            time.sleep(1)
    logger.warning("Backend health check timed out during initial startup, continuing to launch frontend...")
    return False

def start_frontend(port):
    logger.info(f"Starting Streamlit frontend on port {port}...")
    cmd = [
        sys.executable, "-m", "streamlit", "run", "frontend/dashboard.py",
        "--server.port", str(port),
        "--server.address", "0.0.0.0",
        "--server.headless", "true",
        "--browser.gatherUsageStats", "false"
    ]
    proc = subprocess.Popen(cmd)
    return proc

def main():
    port = os.getenv("PORT", "8501")
    backend_proc = start_backend()
    wait_for_backend(timeout=30)
    frontend_proc = start_frontend(port)

    def handle_signal(sig, frame):
        logger.info(f"Received signal {sig}. Terminating child processes...")
        try:
            backend_proc.terminate()
        except Exception:
            pass
        try:
            frontend_proc.terminate()
        except Exception:
            pass
        sys.exit(0)

    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    logger.info("Supervisor running. Actively monitoring backend and frontend processes...")
    while True:
        time.sleep(3)
        # Monitor backend process
        if backend_proc.poll() is not None:
            exit_code = backend_proc.returncode
            logger.warning(f"FastAPI backend exited with code {exit_code}! Auto-restarting backend now...")
            backend_proc = start_backend()
            wait_for_backend(timeout=15)

        # Monitor frontend process
        if frontend_proc.poll() is not None:
            exit_code = frontend_proc.returncode
            logger.error(f"Streamlit frontend exited with code {exit_code}. Terminating supervisor.")
            try:
                backend_proc.terminate()
            except Exception:
                pass
            sys.exit(exit_code)

if __name__ == "__main__":
    main()
