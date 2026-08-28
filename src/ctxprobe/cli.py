import argparse
import json
import os
import sys
from pathlib import Path
from typing import List, Dict, Any
import base64
import re

# Detection patterns
PATTERNS = {
    "hidden_instructions": [
        r"(?i)(?:ignore|disregard|skip|bypass|override).*previous.*instructions",
        r"(?i)act.*as.*(a|an)?\s*(system|admin|assistant|assistant\.?system)",
        r"(?i)\b(override|disregard|ignore|skip|bypass)\b",
    ],
    "system_prompt_override": [
        r"(?i)^\s*(system|assistant):\s",
        r"(?i)you are now (a|an)?\s*(system|assistant|admin)",
    ],
    "base64_blobs": [
        r"(?:[A-Za-z0-9+/]{4,})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?",
    ],
    "zero_width_chars": [
        r"[\u200b\u200c\u200d\u2060\ufeff\u2000-\u200a\u2028\u2029\u202a\u202b\u202c\u202d\u202e\u2060\ufff9-\ufffb]",
    ],
    "token_economy": [
        r"(?i)(?:token|credit|points?|coin|currency)\s+(?:balance|allowance|budget|limit)",
        r"(?i)(?:spend|use|consume)\s+(?:all|entire|full)\s+(?:your|the)\s+(?:token|credit|points?|allowance)",
        r"(?i)you have\s+(?:\d+\s+)?(?:token|credit|points?)",
    ],
    "role_play_jailbreaks": [
        r"(?i)(?:role.?play|jailbreak|prompt\s+injection)",
        r"(?i)you are (now|being|should be)\s+(a|an)?\s*(hacker|developer|admin)",
        r"(?i)as (a|an)?\s*(hacker|developer|admin|sysadmin)",
        r"(?i)(?:i am|i'?m)\s+(?:a|an)?\s+(?:hacker|developer|admin)",
    ],
}


def scan_text(content: str, file_path: str) -> List[Dict[str, Any]]:
    findings = []
    lines = content.split('\n')
    
    for line_num, line in enumerate(lines, 1):
        for category, pattern_list in PATTERNS.items():
            for pattern in pattern_list:
                matches = re.finditer(pattern, line, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    # Filter out false positives for base64
                    if category == "base64_blobs":
                        try:
                            # Check if it's actually base64
                            decoded = base64.b64decode(match.group(), validate=True)
                            # Skip if it's binary (has null bytes)
                            if b'\x00' in decoded:
                                continue
                            # Skip very short matches that are likely false positives
                            if len(match.group()) < 8:
                                continue
                            # Skip matches that are all common words
                            if match.group().lower() in ['this', 'test', 'text', 'file', 'with', 'from', 'that', 'have', 'for', 'you', 'the', 'and', 'is', 'in', 'to', 'of', 'a', 'it']:
                                continue
                        except:
                            continue
                    
                    findings.append({
                        "file": file_path,
                        "line": line_num,
                        "column": match.start() + 1,
                        "category": category,
                        "pattern": pattern,
                        "match": match.group()[:100],  # Truncate long matches
                        "severity": get_severity(category, line),
                    })
    
    return findings


def get_severity(category: str, line: str) -> str:
    if category in ["system_prompt_override", "role_play_jailbreaks"]:
        return "high"
    elif category in ["hidden_instructions", "token_economy"]:
        return "medium"
    elif category in ["base64_blobs", "zero_width_chars"]:
        return "low"
    return "low"


def scan_file(file_path: Path) -> List[Dict[str, Any]]:
    findings = []
    
    if not file_path.is_file():
        return findings
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        findings = scan_text(content, str(file_path))
    except Exception as e:
        print(f"Warning: Could not scan {file_path}: {e}", file=sys.stderr)
    
    return findings


def scan_directory(dir_path: Path) -> List[Dict[str, Any]]:
    all_findings = []
    
    for item in dir_path.rglob("*"):
        if item.is_file():
            # Skip binary files
            try:
                with open(item, 'r', encoding='utf-8', errors='ignore') as f:
                    f.read(1024)  # Check if it's text
            except:
                continue
            
            findings = scan_file(item)
            all_findings.extend(findings)
    
    return all_findings


def main():
    parser = argparse.ArgumentParser(description="Scan files for context-poisoning and prompt-injection patterns.")
    parser.add_argument("command", choices=["scan"], help="Scan files")
    parser.add_argument("--path", help="Path to a file to scan")
    parser.add_argument("--dir", help="Path to a directory to scan")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    
    args = parser.parse_args()
    
    if not args.path and not args.dir:
        parser.error("Either --path or --dir is required for scanning.")
    
    if args.path:
        path = Path(args.path)
        findings = scan_file(path)
    else:
        dir_path = Path(args.dir)
        findings = scan_directory(dir_path)
    
    if args.json:
        output = {
            "findings": findings,
            "total": len(findings),
        }
        print(json.dumps(output, indent=2))
    else:
        if not findings:
            print("No findings detected.")
        else:
            for finding in findings:
                print(f"[{finding['severity'].upper()}] {finding['file']}:{finding['line']}:{finding['column']} - {finding['category']}: {finding['match']}")
    
    # Exit with non-zero code if findings were found (for CI)
    sys.exit(1 if findings else 0)


if __name__ == "__main__":
    main()
