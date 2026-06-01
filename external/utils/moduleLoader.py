import yaml
import os
import glob

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
MODULES_DIR = os.path.join(ROOT_DIR, "modules")

def load_module(name: str, file: str) -> dict:
    """Load satu yaml dari modules/{name}/{file}.yaml"""
    path = os.path.join(MODULES_DIR, name, f"{file}.yaml")
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)

def load_all_modules(module_id=None) -> list[dict]:
    """Load semua yaml dari semua subfolder modules/"""
    modules = []
    for path in glob.glob(os.path.join(MODULES_DIR, "*", "*.yaml")):
        module = _load_file(path)
        if module_id is None or module.get("id") == module_id:
            modules.append(module)
    return modules

def _load_file(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)