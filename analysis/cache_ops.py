"""analysis.cache_ops — split from analysis monolith."""
import os
import shutil
import glob
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def backup_cache(cache_file=None, backup_dir=None, max_backups=10):
    """Create a timestamped backup of the IP cache file.

    Caminhos padrão ancorados na raiz do projeto: relativos, o backup copiava
    o cache do diretório de trabalho — não necessariamente o que o app usa.
    """
    cache_file = cache_file or os.path.join(_ROOT, 'ip_cache.json')
    backup_dir = backup_dir or os.path.join(_ROOT, 'cache_backups')
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


