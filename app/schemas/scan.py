from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, ConfigDict

class ScanCreateRequest(BaseModel):
    target_url: str
    max_depth: Optional[int] = 3
    max_pages: Optional[int] = 50
    webhook_url: Optional[str] = None

class FindingResponse(BaseModel):
    id: int
    scan_id: int
    url: str
    rule_id: str
    title: str
    severity: str
    category: str
    description: str
    evidence: Optional[str]
    remediation: str
    cwe_id: Optional[str]

    model_config = ConfigDict(from_attributes=True)

class CrawledURLResponse(BaseModel):
    id: int
    url: str
    status_code: Optional[int]
    content_type: Optional[str]
    response_time_ms: float

    model_config = ConfigDict(from_attributes=True)

class ScanResponse(BaseModel):
    id: int
    target_url: str
    status: str
    security_score: Optional[float] = 100.0
    total_urls_crawled: Optional[int] = 0
    total_findings: Optional[int] = 0
    critical_count: Optional[int] = 0
    high_count: Optional[int] = 0
    medium_count: Optional[int] = 0
    low_count: Optional[int] = 0
    info_count: Optional[int] = 0
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    duration_seconds: Optional[float] = 0.0
    error_message: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)

class ScanDetailResponse(ScanResponse):
    findings: List[FindingResponse] = []
    crawled_urls: List[CrawledURLResponse] = []

# Scheduled Scan Schemas
class ScheduleCreateRequest(BaseModel):
    target_url: str
    interval_hours: Optional[int] = 24
    max_depth: Optional[int] = 3
    max_pages: Optional[int] = 50

class ScheduleResponse(BaseModel):
    id: int
    target_url: str
    interval_hours: int
    max_depth: int
    max_pages: int
    is_active: bool
    last_run: Optional[datetime] = None
    next_run: Optional[datetime] = None
    created_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)

class NotificationTestRequest(BaseModel):
    webhook_url: str
