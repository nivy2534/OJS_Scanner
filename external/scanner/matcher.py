import re

def match_response(content, matchers):
    findings = []
    for m in matchers:
        if m["type"] == "word":
            for w in m["words"]:
                findings.append(f"WORD MATCH: {w}")
    
        elif m["type"] == "regex":
            for r in m["words"]:
                if re.search(r, content):
                    findings.append(f"REGEX MATCH: {r}")
    
    return findings