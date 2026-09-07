import os
from pydantic import BaseModel

class Settings(BaseModel):
    PROJECT_NAME: str = "Web Application Security Scanner"
    VERSION: str = "1.0.0"
    API_PREFIX: str = "/api"
    
    # Database
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./scanner.db")
    
    # Default Scanner Settings
    DEFAULT_MAX_DEPTH: int = 3
    DEFAULT_MAX_PAGES: int = 50
    DEFAULT_TIMEOUT_SECONDS: float = 10.0
    DEFAULT_USER_AGENT: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 (Security Audit Engine)"
    
    # Reports directory
    REPORTS_DIR: str = os.getenv("REPORTS_DIR", "./reports_output")

settings = Settings()

os.makedirs(settings.REPORTS_DIR, exist_ok=True)
