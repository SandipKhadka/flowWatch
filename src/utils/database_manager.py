# src/utils/database_manager.py - Fixed syntax error
import sqlite3
import pandas as pd
from datetime import datetime, timedelta
from typing import List, Dict, Optional
import json
import os

class DatabaseManager:
    """SQLite database manager for storing alerts and statistics"""
    
    def __init__(self, db_path="data/ids_database.db"):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.init_database()
    
    def init_database(self):
        """Initialize database tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # 1. Alerts table (removed inline INDEX - will create separately)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME NOT NULL,
                source_ip TEXT NOT NULL,
                attack_type TEXT NOT NULL,
                confidence REAL NOT NULL,
                severity INTEGER DEFAULT 5,
                packet_id INTEGER,
                details TEXT,
                is_resolved BOOLEAN DEFAULT 0,
                resolved_at DATETIME
            )
        ''')
        
        # Create indexes separately
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON alerts(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_source_ip ON alerts(source_ip)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_attack_type ON alerts(attack_type)')
        
        # 2. Statistics table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS statistics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME NOT NULL,
                total_packets INTEGER DEFAULT 0,
                total_threats INTEGER DEFAULT 0,
                detection_rate REAL DEFAULT 0,
                risk_score REAL DEFAULT 0,
                active_alerts INTEGER DEFAULT 0,
                cpu_usage REAL,
                memory_usage REAL
            )
        ''')
        
        # Create index for statistics
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_stats_timestamp ON statistics(timestamp)')
        
        # 3. Attack patterns table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS attack_patterns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pattern_name TEXT NOT NULL,
                attack_type TEXT NOT NULL,
                first_seen DATETIME NOT NULL,
                last_seen DATETIME NOT NULL,
                frequency INTEGER DEFAULT 1,
                severity INTEGER DEFAULT 5,
                pattern_signature TEXT,
                confidence REAL DEFAULT 0
            )
        ''')
        
        # Create unique constraint separately
        cursor.execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_pattern_unique ON attack_patterns(pattern_name, attack_type)')
        
        # 4. Blocked IPs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS blocked_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL UNIQUE,
                reason TEXT,
                blocked_at DATETIME NOT NULL,
                expires_at DATETIME,
                attack_count INTEGER DEFAULT 1,
                is_active BOOLEAN DEFAULT 1
            )
        ''')
        
        # 5. Settings table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at DATETIME NOT NULL,
                description TEXT
            )
        ''')
        
        # Insert default settings if not exists
        cursor.execute('''
            INSERT OR IGNORE INTO settings (key, value, updated_at, description)
            VALUES 
                ('confidence_threshold', '0.85', datetime('now'), 'Minimum confidence for alerts'),
                ('alert_cooldown', '60', datetime('now'), 'Cooldown seconds for same IP'),
                ('auto_block', 'true', datetime('now'), 'Auto-block malicious IPs'),
                ('block_duration', '3600', datetime('now'), 'Block duration in seconds')
        ''')
        
        conn.commit()
        conn.close()
        print("✅ Database initialized successfully")
    
    def save_alert(self, alert: Dict) -> int:
        """Save alert to database and return ID"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        from src.utils.attack_mapper import AttackMapper
        severity = AttackMapper.get_severity_score(alert['attack_type'])
        
        try:
            cursor.execute('''
                INSERT INTO alerts 
                (timestamp, source_ip, attack_type, confidence, severity, packet_id, details, is_resolved)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                alert['timestamp'],
                alert.get('source_ip', 'Unknown'),
                alert['attack_type'],
                alert['confidence'],
                severity,
                alert.get('packet_id', 0),
                json.dumps(alert),
                0
            ))
            
            alert_id = cursor.lastrowid
            conn.commit()
            return alert_id
            
        except Exception as e:
            print(f"Error saving alert: {e}")
            return -1
        finally:
            conn.close()
    
    def get_alerts(self, hours: int = 24, limit: int = 100, severity: int = None) -> pd.DataFrame:
        """Get alerts with filters"""
        conn = sqlite3.connect(self.db_path)
        
        query = '''
            SELECT id, timestamp, source_ip, attack_type, confidence, severity, 
                   is_resolved, resolved_at
            FROM alerts
            WHERE timestamp >= datetime('now', '-' || ? || ' hours')
        '''
        params = [hours]
        
        if severity is not None:
            query += " AND severity >= ?"
            params.append(severity)
        
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        df = pd.read_sql_query(query, conn, params=params)
        conn.close()
        return df
    
    def get_alert_by_id(self, alert_id: int) -> Dict:
        """Get single alert by ID"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,))
        row = cursor.fetchone()
        conn.close()
        
        return dict(row) if row else None
    
    def resolve_alert(self, alert_id: int, resolution_note: str = None):
        """Mark alert as resolved"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE alerts 
            SET is_resolved = 1, resolved_at = datetime('now'), details = ?
            WHERE id = ?
        ''', (resolution_note, alert_id))
        
        conn.commit()
        conn.close()
    
    def save_statistics(self, stats: Dict):
        """Save system statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO statistics 
            (timestamp, total_packets, total_threats, detection_rate, risk_score, active_alerts)
            VALUES (datetime('now'), ?, ?, ?, ?, ?)
        ''', (
            stats.get('packets_processed', 0),
            stats.get('threats_detected', 0),
            stats.get('detection_rate', 0),
            stats.get('risk_score', 0),
            len(stats.get('active_alerts', []))
        ))
        
        conn.commit()
        conn.close()
    
    def get_statistics(self, hours: int = 24) -> pd.DataFrame:
        """Get historical statistics"""
        conn = sqlite3.connect(self.db_path)
        
        query = '''
            SELECT timestamp, total_packets, total_threats, detection_rate, risk_score
            FROM statistics
            WHERE timestamp >= datetime('now', '-' || ? || ' hours')
            ORDER BY timestamp
        '''
        
        df = pd.read_sql_query(query, conn, params=[hours])
        conn.close()
        return df
    
    def update_attack_pattern(self, attack_type: str, source_ip: str):
        """Update or create attack pattern"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        pattern_name = f"{attack_type}_from_{source_ip.split('.')[0]}_{source_ip.split('.')[1]}"
        
        cursor.execute('''
            INSERT INTO attack_patterns 
            (pattern_name, attack_type, first_seen, last_seen, frequency, severity)
            VALUES (?, ?, datetime('now'), datetime('now'), 1, ?)
            ON CONFLICT(pattern_name, attack_type) DO UPDATE SET
                last_seen = datetime('now'),
                frequency = frequency + 1
        ''', (pattern_name, attack_type, 5))
        
        conn.commit()
        conn.close()
    
    def get_attack_patterns(self, limit: int = 20) -> pd.DataFrame:
        """Get frequent attack patterns"""
        conn = sqlite3.connect(self.db_path)
        
        query = '''
            SELECT attack_type, COUNT(*) as count, 
                   MIN(first_seen) as first_seen, 
                   MAX(last_seen) as last_seen,
                   AVG(severity) as avg_severity
            FROM attack_patterns
            GROUP BY attack_type
            ORDER BY count DESC
            LIMIT ?
        '''
        
        df = pd.read_sql_query(query, conn, params=[limit])
        conn.close()
        return df
    
    def block_ip(self, ip: str, reason: str, duration_seconds: int = 3600) -> bool:
        """Add IP to block list"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT OR REPLACE INTO blocked_ips 
                (ip_address, reason, blocked_at, expires_at, is_active)
                VALUES (?, ?, datetime('now'), datetime('now', '+' || ? || ' seconds'), 1)
            ''', (ip, reason, duration_seconds))
            
            conn.commit()
            return True
        except Exception as e:
            print(f"Error blocking IP: {e}")
            return False
        finally:
            conn.close()
    
    def unblock_ip(self, ip: str) -> bool:
        """Remove IP from block list"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE blocked_ips 
            SET is_active = 0, expires_at = datetime('now')
            WHERE ip_address = ?
        ''', (ip,))
        
        conn.commit()
        conn.close()
        return True
    
    def get_blocked_ips(self, active_only: bool = True) -> List[str]:
        """Get list of blocked IPs"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if active_only:
            cursor.execute('''
                SELECT ip_address FROM blocked_ips 
                WHERE is_active = 1 AND (expires_at IS NULL OR expires_at > datetime('now'))
            ''')
        else:
            cursor.execute('SELECT ip_address FROM blocked_ips')
        
        ips = [row[0] for row in cursor.fetchall()]
        conn.close()
        return ips
    
    def get_setting(self, key: str, default: str = None) -> str:
        """Get a setting value"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT value FROM settings WHERE key = ?", (key,))
        row = cursor.fetchone()
        conn.close()
        
        return row[0] if row else default
    
    def update_setting(self, key: str, value: str, description: str = None):
        """Update a setting"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if description:
            cursor.execute('''
                UPDATE settings 
                SET value = ?, updated_at = datetime('now'), description = ?
                WHERE key = ?
            ''', (value, description, key))
        else:
            cursor.execute('''
                UPDATE settings 
                SET value = ?, updated_at = datetime('now')
                WHERE key = ?
            ''', (value, key))
        
        conn.commit()
        conn.close()
    
    def get_attack_statistics(self, days: int = 7) -> Dict:
        """Get comprehensive attack statistics"""
        conn = sqlite3.connect(self.db_path)
        
        # Total attacks by type
        query1 = f'''
            SELECT attack_type, COUNT(*) as count, AVG(confidence) as avg_confidence
            FROM alerts
            WHERE timestamp >= datetime('now', '-{days} days')
            GROUP BY attack_type
            ORDER BY count DESC
        '''
        df1 = pd.read_sql_query(query1, conn)
        
        # Hourly distribution
        query2 = f'''
            SELECT strftime('%H', timestamp) as hour, COUNT(*) as count
            FROM alerts
            WHERE timestamp >= datetime('now', '-{days} days')
            GROUP BY hour
            ORDER BY hour
        '''
        df2 = pd.read_sql_query(query2, conn)
        
        # Top attackers
        query3 = f'''
            SELECT source_ip, COUNT(*) as attack_count, 
                   GROUP_CONCAT(DISTINCT attack_type) as attack_types
            FROM alerts
            WHERE timestamp >= datetime('now', '-{days} days')
            GROUP BY source_ip
            ORDER BY attack_count DESC
            LIMIT 10
        '''
        df3 = pd.read_sql_query(query3, conn)
        
        conn.close()
        
        return {
            'total_attacks': len(df1),
            'by_type': df1.to_dict('records'),
            'hourly_distribution': df2.to_dict('records'),
            'top_attackers': df3.to_dict('records'),
            'avg_severity': df1['count'].mean() if not df1.empty else 0
        }
    
    def get_daily_summary(self, days: int = 30) -> pd.DataFrame:
        """Get daily attack summary for reports"""
        conn = sqlite3.connect(self.db_path)
        
        query = f'''
            SELECT 
                DATE(timestamp) as date,
                COUNT(*) as total_attacks,
                COUNT(DISTINCT source_ip) as unique_attackers,
                AVG(confidence) as avg_confidence,
                AVG(severity) as avg_severity,
                SUM(CASE WHEN severity >= 8 THEN 1 ELSE 0 END) as critical_attacks
            FROM alerts
            WHERE timestamp >= datetime('now', '-{days} days')
            GROUP BY DATE(timestamp)
            ORDER BY date DESC
        '''
        
        df = pd.read_sql_query(query, conn)
        conn.close()
        return df
    
    def cleanup_old_data(self, days: int = 30):
        """Delete old data to keep database size manageable"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Delete old alerts
        cursor.execute(f'''
            DELETE FROM alerts
            WHERE timestamp < datetime('now', '-{days} days') AND is_resolved = 1
        ''')
        
        # Delete old statistics
        cursor.execute(f'''
            DELETE FROM statistics
            WHERE timestamp < datetime('now', '-{days} days')
        ''')
        
        # Delete expired blocks
        cursor.execute('''
            UPDATE blocked_ips
            SET is_active = 0
            WHERE expires_at < datetime('now')
        ''')
        
        deleted_alerts = cursor.rowcount
        conn.commit()
        conn.close()
        
        print(f"🧹 Cleaned up {deleted_alerts} old records")
        return deleted_alerts
    
    def get_database_stats(self) -> Dict:
        """Get database statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        tables = ['alerts', 'statistics', 'attack_patterns', 'blocked_ips']
        stats = {}
        
        for table in tables:
            cursor.execute(f"SELECT COUNT(*) FROM {table}")
            stats[f'{table}_count'] = cursor.fetchone()[0]
        
        stats['db_size_mb'] = os.path.getsize(self.db_path) / (1024 * 1024) if os.path.exists(self.db_path) else 0
        
        conn.close()
        return stats
    
    def export_to_csv(self, table_name: str, output_file: str = None) -> str:
        """Export table to CSV"""
        if output_file is None:
            output_file = f"exports/{table_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        
        conn = sqlite3.connect(self.db_path)
        df = pd.read_sql_query(f"SELECT * FROM {table_name}", conn)
        df.to_csv(output_file, index=False)
        conn.close()
        
        return output_file

def get_all_alerts(self, limit=10000, offset=0) -> pd.DataFrame:
    """Get all alerts with pagination"""
    conn = sqlite3.connect(self.db_path)
    query = f'''
        SELECT id, timestamp, source_ip, attack_type, confidence, severity
        FROM alerts
        ORDER BY timestamp DESC
        LIMIT ? OFFSET ?
    '''
    df = pd.read_sql_query(query, conn, params=[limit, offset])
    conn.close()
    return df

def get_alert_count_by_date(self, days=30) -> pd.DataFrame:
    """Get alert count grouped by date"""
    conn = sqlite3.connect(self.db_path)
    query = f'''
        SELECT date(timestamp) as date, 
               COUNT(*) as alert_count,
               COUNT(DISTINCT source_ip) as unique_attackers
        FROM alerts
        WHERE timestamp >= datetime('now', '-{days} days')
        GROUP BY date(timestamp)
        ORDER BY date DESC
    '''
    df = pd.read_sql_query(query, conn)
    conn.close()
    return df

def get_database_info(self) -> dict:
    """Get database information"""
    conn = sqlite3.connect(self.db_path)
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) FROM alerts")
    alerts_count = cursor.fetchone()[0]
    
    cursor.execute("SELECT MIN(timestamp), MAX(timestamp) FROM alerts")
    min_date, max_date = cursor.fetchone()
    
    cursor.execute("SELECT COUNT(DISTINCT attack_type) FROM alerts")
    attack_types = cursor.fetchone()[0]
    
    conn.close()
    
    return {
        'alerts_count': alerts_count,
        'min_date': min_date,
        'max_date': max_date,
        'attack_types': attack_types,
        'db_size_mb': os.path.getsize(self.db_path) / (1024 * 1024) if os.path.exists(self.db_path) else 0
    }
