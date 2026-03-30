"""Intentional B602 — subprocess call with shell=True."""
import subprocess

def run_command(user_input: str) -> str:
    result = subprocess.run(user_input, shell=True, capture_output=True, text=True)
    return result.stdout
