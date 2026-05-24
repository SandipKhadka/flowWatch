"""
Application configuration management
"""

from dataclasses import dataclass, field
from typing import Dict, Any, Optional
from enum import Enum
import os


class AppMode(Enum):
    """Application detection modes"""
    DEMO = "Demo Mode"
    LIVE = "Live Capture"


class TimePeriod(Enum):
    """Time period options for reports"""
    LAST_24_HOURS = ("Last 24 Hours", 24)
    LAST_7_DAYS = ("Last 7 Days", 168)
    LAST_30_DAYS = ("Last 30 Days", 720)
    ALL_TIME = ("All Time", 8760)
    
    def __init__(self, label: str, hours: int):
        self.label = label
        self.hours = hours


class AlertSeverity(Enum):
    """Alert severity levels"""
    ALL = ("All", 0, 10)
    CRITICAL = ("Critical (8-10)", 8, 10)
    HIGH = ("High (5-7)", 5, 7)
    MEDIUM = ("Medium (3-4)", 3, 4)
    
    def __init__(self, label: str, min_score: int, max_score: int):
        self.label = label
        self.min_score = min_score
        self.max_score = max_score


@dataclass
class UIConfig:
    """UI configuration settings"""
    # Theme
    theme: str = "dark"
    primary_color: str = "#667eea"
    secondary_color: str = "#764ba2"
    
    # Layout
    sidebar_initial_state: str = "expanded"
    page_layout: str = "wide"
    
    # Refresh
    auto_refresh_interval: int = 2  # seconds
    default_auto_refresh: bool = True
    
    # Display
    max_alerts_display: int = 50
    chart_height: int = 400
    metric_card_height: int = 120


@dataclass
class DetectionConfig:
    """Detection system configuration"""
    min_confidence: float = 0.88
    min_severity: int = 5
    max_alerts_per_minute: int = 8
    model_dir: str = "src/models"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'min_confidence': self.min_confidence,
            'min_severity': self.min_severity,
            'max_alerts_per_minute': self.max_alerts_per_minute
        }


@dataclass
class DatabaseConfig:
    """Database configuration"""
    db_path: str = "data/ids_database.db"
    backup_enabled: bool = True
    backup_interval_hours: int = 24
    max_records: int = 100000


@dataclass
class ExportConfig:
    """Export configuration"""
    export_dir: str = "exports"
    csv_enabled: bool = True
    json_enabled: bool = True
    excel_enabled: bool = True
    pdf_enabled: bool = True


class AppConfig:
    """Main application configuration"""
    
    def __init__(self):
        self.ui = UIConfig()
        self.detection = DetectionConfig()
        self.database = DatabaseConfig()
        self.export = ExportConfig()
        
        # Create directories if needed
        self._ensure_directories()
    
    def _ensure_directories(self):
        """Ensure required directories exist"""
        os.makedirs(self.export.export_dir, exist_ok=True)
        os.makedirs(os.path.dirname(self.database.db_path), exist_ok=True)
    
    def update_detection_config(self, **kwargs):
        """Update detection configuration"""
        for key, value in kwargs.items():
            if hasattr(self.detection, key):
                setattr(self.detection, key, value)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert entire config to dictionary"""
        return {
            'ui': self.ui.__dict__,
            'detection': self.detection.__dict__,
            'database': self.database.__dict__,
            'export': self.export.__dict__
        }


# Global config instance
config = AppConfig()
