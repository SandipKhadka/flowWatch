"""
Centralized session state management with type safety
"""

from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime
import streamlit as st
from ..detection.real_time_detector import RealTimeIDS
from ..utils.database_manager import DatabaseManager
from ..utils.alert_manager import AlertManager


@dataclass
class SessionData:
    """Type-safe session data structure"""
    # Core components
    detector: Optional[RealTimeIDS] = None
    db: Optional[DatabaseManager] = None
    alert_manager: Optional[AlertManager] = None
    
    # State flags
    running: bool = False
    historical_loaded: bool = False
    auto_refresh: bool = True
    
    # Data
    alerts: List[Dict] = field(default_factory=list)
    model_info: Optional[Dict] = None
    quick_filter: Optional[str] = None
    
    # Filters
    selected_time_period: str = "Last 24 Hours"
    selected_severity: str = "All"
    min_confidence_filter: float = 0.85
    selected_attack_type: str = "All"
    selected_source_ip: str = "All"
    
    # UI State
    sidebar_collapsed: bool = False
    active_tab: int = 0
    last_refresh: Optional[datetime] = None


class SessionStateManager:
    """Manage Streamlit session state with persistence"""
    
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        if not hasattr(self, 'initialized'):
            self.initialized = True
            self._initialize_session()
    
    def _initialize_session(self):
        """Initialize all session state variables"""
        # Get default data from SessionData
        default_data = SessionData()
        
        # Initialize each variable individually using the correct Streamlit pattern
        # This ensures each variable is properly initialized before access
        
        # Core components
        if 'detector' not in st.session_state:
            st.session_state.detector = default_data.detector
        
        if 'db' not in st.session_state:
            st.session_state.db = default_data.db or DatabaseManager()
        
        if 'alert_manager' not in st.session_state:
            st.session_state.alert_manager = default_data.alert_manager or AlertManager()
        
        # State flags
        if 'running' not in st.session_state:
            st.session_state.running = default_data.running
        
        if 'historical_loaded' not in st.session_state:
            st.session_state.historical_loaded = default_data.historical_loaded
        
        if 'auto_refresh' not in st.session_state:
            st.session_state.auto_refresh = default_data.auto_refresh
        
        # Data
        if 'alerts' not in st.session_state:
            st.session_state.alerts = default_data.alerts
        
        if 'model_info' not in st.session_state:
            st.session_state.model_info = default_data.model_info
        
        if 'quick_filter' not in st.session_state:
            st.session_state.quick_filter = default_data.quick_filter
        
        # Filters
        if 'selected_time_period' not in st.session_state:
            st.session_state.selected_time_period = default_data.selected_time_period
        
        if 'selected_severity' not in st.session_state:
            st.session_state.selected_severity = default_data.selected_severity
        
        if 'min_confidence_filter' not in st.session_state:
            st.session_state.min_confidence_filter = default_data.min_confidence_filter
        
        if 'selected_attack_type' not in st.session_state:
            st.session_state.selected_attack_type = default_data.selected_attack_type
        
        if 'selected_source_ip' not in st.session_state:
            st.session_state.selected_source_ip = default_data.selected_source_ip
        
        # UI State
        if 'sidebar_collapsed' not in st.session_state:
            st.session_state.sidebar_collapsed = default_data.sidebar_collapsed
        
        if 'active_tab' not in st.session_state:
            st.session_state.active_tab = default_data.active_tab
        
        if 'last_refresh' not in st.session_state:
            st.session_state.last_refresh = default_data.last_refresh
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get a session state value"""
        return st.session_state.get(key, default)
    
    def set(self, key: str, value: Any) -> None:
        """Set a session state value"""
        st.session_state[key] = value
    
    def update(self, **kwargs) -> None:
        """Update multiple session state values"""
        for key, value in kwargs.items():
            if key in st.session_state:
                st.session_state[key] = value
    
    def add_alert(self, alert: Dict) -> None:
        """Add an alert with deduplication"""
        existing_keys = {
            (a['timestamp'], a['source_ip'], a['attack_type']) 
            for a in st.session_state.alerts
        }
        
        key = (alert['timestamp'], alert['source_ip'], alert['attack_type'])
        if key not in existing_keys:
            st.session_state.alerts.append(alert)
            
            # Save to database
            if st.session_state.db:
                st.session_state.db.save_alert(alert)
            
            # Process through alert manager
            if st.session_state.alert_manager:
                st.session_state.alert_manager.process_alert(alert)
    
    def clear_alerts(self) -> None:
        """Clear all alerts from session"""
        st.session_state.alerts = []
    
    def is_running(self) -> bool:
        """Check if detection is running"""
        # Safe access - variable is guaranteed to be initialized
        return st.session_state.get('running', False)
    
    def get_alerts_dataframe(self):
        """Get alerts as pandas DataFrame"""
        import pandas as pd
        if st.session_state.alerts:
            df = pd.DataFrame(st.session_state.alerts)
            if 'timestamp' in df.columns:
                df['timestamp'] = pd.to_datetime(df['timestamp'])
            return df
        return pd.DataFrame()
    
    def reset(self) -> None:
        """Reset all session state (except critical components)"""
        critical_keys = ['db', 'alert_manager']
        preserved = {k: st.session_state[k] for k in critical_keys if k in st.session_state}
        
        for key in list(st.session_state.keys()):
            if key not in critical_keys:
                del st.session_state[key]
        
        # Reinitialize
        self._initialize_session()
        
        # Restore critical components
        for key, value in preserved.items():
            st.session_state[key] = value


# Global session manager instance
session = SessionStateManager()
