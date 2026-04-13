import yaml

def load_rule(path):
    with open(path, "r") as f:
        return yaml.safe_load(f)