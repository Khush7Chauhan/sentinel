import json
from pathlib import Path
from typing import List
from src.models import PackageRecord

def parse_target_directory(target_path: Path) -> List[PackageRecord]:
    packages = []

    pkg_json = target_path / "package.json"
    if pkg_json.exists():
        try:
            with open(pkg_json, "r", encoding="utf-8") as f:
                data = json.load(f)
                deps = data.get("dependencies", {})
                dev_deps = data.get("devDependencies", {})
                
                for name, version in {**deps, **dev_deps}.items():
                    clean_version = version.strip("^~<>=")
                    packages.append(PackageRecord(
                        name=name, version=clean_version, ecosystem="npm", 
                        direct=True, depth=0, source_file="package.json"
                    ))
        except Exception as e:
            print(f"Error parsing package.json: {e}")

    req_txt = target_path / "requirements.txt"
    if req_txt.exists():
        try:
            with open(req_txt, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.split("#")[0].strip() 
                    if line:
                        parts = line.split("==")
                        name = parts[0].strip()
                        version = parts[1].strip() if len(parts) > 1 else "latest"
                        
                        packages.append(PackageRecord(
                            name=name, version=version, ecosystem="pypi", 
                            direct=True, depth=0, source_file="requirements.txt"
                        ))
        except Exception as e:
            print(f"Error parsing requirements.txt: {e}")
        
    return packages