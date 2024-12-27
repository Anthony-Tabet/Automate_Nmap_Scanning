# src/nmap_automator/runner.py
import os
from dotenv import load_dotenv

from .interpretors import GeminiInterpretor
from .scanner import NmapScanner

def main():
    load_dotenv()
    scanner = NmapScanner()
    interpretor = GeminiInterpretor(
        name="Gemini",
        api_key=os.getenv("GOOGLE_API_KEY")
    )
    interpretor.configure()
    target = "www.megacorpone.com"
    save_dir = "results/"
    results = scanner.scan(target, "-A -T3 -v", save_dir)
    res = interpretor.interpret_restricted(results)
    print()
    print(res)

if __name__ == "__main__":
    main()