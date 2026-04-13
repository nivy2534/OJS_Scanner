import requests
from rule import *
class Scanner:
    def __init__(self, rules):
        self.rules = rules
        self.session = requests.Session()

    def scan(self, domain, endpoints):
        findings = []

        for rule in self.rules:
            result = rule.run(self.session, domain, endpoints)

            if result:
                findings.append(result)
            
        return findings
        