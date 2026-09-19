import os
import tarfile
import httpx
from pathlib import Path
from tempfile import mkdtemp
from src.config import RULES
from src.models import PackageRecord

CACHE_DIR = Path.home() / ".sentinel" / "cache"
MAX_SIZE_BYTES = RULES["behavior_limits"]["max_tarball_mb"] * 1024 * 1024

def fetch_and_extract(package: PackageRecord) -> Path | None:
    if package.ecosystem != "pypi":
        return None  

    ecosystem_cache = CACHE_DIR / package.ecosystem
    ecosystem_cache.mkdir(parents=True, exist_ok=True)
    
    tarball_path = ecosystem_cache / f"{package.name}@{package.version}.tar.gz"
    extract_dir = ecosystem_cache / f"extracted_{package.name}_{package.version}"

    if extract_dir.exists():
        return extract_dir

    if not tarball_path.exists():
        url = f"https://pypi.org/pypi/{package.name}/{package.version}/json"
        try:
            resp = httpx.get(url, timeout=5.0)
            resp.raise_for_status()
            urls = resp.json().get("urls", [])
            tarball_url = next((u["url"] for u in urls if u["packagetype"] == "sdist"), None)
            
            if not tarball_url:
                return None
                
            with httpx.stream("GET", tarball_url) as stream:
                stream.raise_for_status()
                with open(tarball_path, "wb") as f:
                    downloaded = 0
                    for chunk in stream.iter_bytes():
                        downloaded += len(chunk)
                        if downloaded > MAX_SIZE_BYTES:
                            tarball_path.unlink()
                            return None
                        f.write(chunk)
        except Exception:
            return None

    try:
        with tarfile.open(tarball_path, "r:gz") as tar:
            tar.extractall(path=extract_dir)
    except Exception:
        return None

    return extract_dir