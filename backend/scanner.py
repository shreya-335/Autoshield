# backend/scanner.py
import subprocess
import json
import os
import shutil

def run_scanners(target_dir: str):
    results = []
    
    # Check if target_dir exists to avoid obvious errors
    if not os.path.exists(target_dir):
        print(f"Error: Target directory {target_dir} does not exist.")
        return results

    # 1. Run Semgrep
    try:
        # Check if semgrep is installed/available in PATH
        # On Windows, we use shell=True to ensure it finds the .exe or .cmd wrapper
        sem_proc = subprocess.run(
            ["semgrep", "scan", "--config=auto", "--json", "."],
            cwd=target_dir, # Run inside the target directory
            capture_output=True, 
            text=True, 
            shell=True 
        )
        
        if sem_proc.stdout.strip():
            sem_data = json.loads(sem_proc.stdout)
            for finding in sem_data.get("results", []):
                results.append({
                    "tool": "semgrep",
                    "file_path": finding['path'],
                    "line": finding['start']['line'],
                    "message": finding['extra']['message'],
                    "severity": finding['extra']['severity']
                })
    except Exception as e:
        print(f"Semgrep Error: {e}")

    # 2. Run ESLint
    try:
        # On Windows, npx often needs to be called as npx.cmd
        # We use shell=True here as well
        es_command = ["npx", "eslint", ".", "--format", "json"]
        
        es_proc = subprocess.run(
            es_command,
            cwd=target_dir,
            capture_output=True, 
            text=True, 
            shell=True
        )
        
        # ESLint returns a 1 exit code if vulnerabilities are found, 
        # so we check stdout regardless of return code.
        if es_proc.stdout.strip():
            es_data = json.loads(es_proc.stdout)
            for file_entry in es_data:
                for msg in file_entry.get("messages", []):
                    # Convert absolute path back to relative if needed
                    rel_path = os.path.relpath(file_entry['filePath'], target_dir)
                    results.append({
                        "tool": "eslint",
                        "file_path": rel_path,
                        "line": msg.get('line', 0),
                        "message": msg['message'],
                        "severity": "WARNING" if msg['severity'] == 1 else "ERROR"
                    })
    except Exception as e:
        print(f"ESLint Error: {e}")

    return results