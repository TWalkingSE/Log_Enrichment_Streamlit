"""analysis.cache_ops — split from analysis monolith."""
import os
import shutil
import glob
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

def backup_cache(cache_file='ip_cache.json', backup_dir='cache_backups', max_backups=10):
    """Create a timestamped backup of the IP cache file."""
    if not os.path.exists(cache_file):
        return None

    os.makedirs(backup_dir, exist_ok=True)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_path = os.path.join(backup_dir, f'ip_cache_{timestamp}.json')
    shutil.copy2(cache_file, backup_path)

    # Rotate: keep only max_backups
    backups = sorted(glob.glob(os.path.join(backup_dir, 'ip_cache_*.json')))
    while len(backups) > max_backups:
        os.remove(backups.pop(0))

    return backup_path


