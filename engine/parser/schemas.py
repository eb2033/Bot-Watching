from datetime import datetime
from pydantic import BaseModel
from typing import Any

class BaseEvent(BaseModel):
    session_id : str
    eventid : str
    timestamp : datetime
    src_ip: str
    raw: dict[str, Any]
    
class SessionConnectEvent(BaseEvent):
    src_port: int
    dst_port: int
    protocol: str
    
class AuthAttemptEvent(BaseEvent):
    username: str
    password: str
    success: bool
    
class CommandEvent(BaseEvent):
    input: str
    
class DownloadEvent(BaseEvent):
    url: str
    filename: str
    file_path: str
    sha256: str
    
class Alert(BaseEvent):
    rule_name:str
    severity:str
    details:str
    
class IPEnrichment(BaseModel):
    src_ip: str
    country: str | None
    city: str | None
    asn: str | None
    org: str | None
    enriched_at: datetime
    