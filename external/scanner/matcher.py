import re
import time

def match_response(content, status_code, elapsed, matchers):
    """
    Return (matched: bool, findings: list[str])
    Semua matchers harus match (AND logic antar matcher).
    Di dalam satu matcher, kondisi bisa OR/AND.
    """
    findings = []

    for m in matchers:
        mtype = m["type"]
        negate = m.get("negate", False)
        condition = m.get("condition", "or")  # default OR dalam satu matcher

        matched = False

        if mtype == "word":
            part = m.get("part", "body")
            target = content if part == "body" else ""
            results = [w for w in m["words"] if w in target]

            matched = (len(results) > 0) if condition == "or" else (len(results) == len(m["words"]))
            if matched:
                findings.extend([f"WORD: {w}" for w in results])

        elif mtype == "regex":
            part = m.get("part", "body")
            target = content if part == "body" else ""
            results = [r for r in m["words"] if re.search(r, target)]

            matched = (len(results) > 0) if condition == "or" else (len(results) == len(m["words"]))
            if matched:
                findings.extend([f"REGEX: {r}" for r in results])

        elif mtype == "status":
            matched = status_code in m["status"]
            if matched:
                findings.append(f"STATUS: {status_code}")

        elif mtype == "time":
            matched = elapsed >= m["duration"]
            if matched:
                findings.append(f"TIME-BASED: {elapsed:.2f}s >= {m['duration']}s")

        # negate: balik logic (misal: pastikan TIDAK ada kata "login")
        if negate:
            matched = not matched

        # AND antar matcher: kalau satu tidak match, langsung stop
        if not matched:
            return False, []

    return len(findings) > 0, findings