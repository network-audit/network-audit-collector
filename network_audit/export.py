"""CSV export helpers."""

import csv
import os
from datetime import datetime


def default_csv_path(suffix):
    """Generate a default CSV path: data/YYYY-MM-DD_HHMM_{suffix}.csv

    The data/ directory is created relative to the current working directory.
    """
    data_dir = os.path.join(os.getcwd(), "data")
    os.makedirs(data_dir, exist_ok=True)
    return os.path.join(data_dir, datetime.now().strftime(f"%Y-%m-%d_%H%M_{suffix}.csv"))


def export_csv(rows, fieldnames, filename):
    """Write a list of row dicts to a CSV file.

    Args:
        rows: List of dicts (each dict is one CSV row).
        fieldnames: Ordered list of column names.
        filename: Output file path.

    Returns:
        The filename written.
    """
    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    return filename
