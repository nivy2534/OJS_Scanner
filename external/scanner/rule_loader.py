import yaml
import os
import glob

BASE_DIR = os.path.join(os.path.dirname(__file__))
ROOT_DIR = os.path.abspath(os.path.join(BASE_DIR, ".." ))
RULES_DIR = os.path.join(ROOT_DIR, "rules")

def load_rule(path):
    with open(path, "r", encoding='utf-8') as f:
        return yaml.safe_load(f)
    
def load_all_rules(rule_ids=None):
    rules = []
    for path in glob.glob(os.path.join(RULES_DIR, "*.yaml")):
        rule = load_rule(path)
        if rule_ids is None or rule["id"] in rule_ids:
            rules.append(rule)
    return rules
