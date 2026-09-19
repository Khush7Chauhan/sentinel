import re
from pathlib import Path
from src.models import PackageRecord

def parse_requirements(file_path: Path) -> list[PackageRecord]:
    if not file_path.exists():
        return []

    records = []
    line_pattern = re.compile(r"^([a-zA-Z0-9_\-\.]+)(?:([=><~!^]{1,2})([a-zA-Z0-9_\-\.]+))?")

    for raw_line in file_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        match = line_pattern.match(line)
        if match:
            pkg_name, operator, version = match.groups()
            records.append(PackageRecord(
                name=pkg_name,
                version=version if operator == "==" else None,
                source_file=str(file_path)
            ))

    return records