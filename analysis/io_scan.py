"""analysis.io_scan — split from analysis monolith."""
import os
import logging

logger = logging.getLogger(__name__)

def scan_folder_for_logs(folder_path, extensions=None):
    """
    Scan a folder for log files to process.

    Returns list of file paths found.
    """
    if not folder_path or not os.path.isdir(folder_path):
        return []

    if extensions is None:
        extensions = ['.txt', '.csv', '.xlsx', '.xls', '.html', '.zip']

    files = []
    for f in os.listdir(folder_path):
        full_path = os.path.join(folder_path, f)
        if os.path.isfile(full_path):
            ext = os.path.splitext(f)[1].lower()
            if ext in extensions:
                files.append(full_path)

    return sorted(files)


