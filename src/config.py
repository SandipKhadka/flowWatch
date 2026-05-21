from pathlib import Path

BASE_DIR = Path(__file__).parent

CONFIG = {
    "dataset_path": str(BASE_DIR / "data" / "NSL_KDD"),
    "model_save_path": str(BASE_DIR / "models"),
    "log_path": str(BASE_DIR / "logs" / "ids.log"),
    
    "features": [
        "duration", "protocol_type", "service", "flag", "src_bytes", 
        "dst_bytes", "land", "wrong_fragment", "urgent", "hot", 
        "num_failed_logins", "logged_in", "num_compromised", "root_shell",
        # Add more later
    ],
    
    "test_size": 0.2,
    "random_state": 42,
    "n_jobs": -1
}
