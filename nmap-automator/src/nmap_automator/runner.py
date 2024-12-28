# src/nmap_automator/runner.py
import os
import datetime
from dotenv import load_dotenv

from nmap_automator.interpretors import InterpretorFactory
from nmap_automator.scanner import NmapScanner
from nmap_automator.config_loader import Config

def main():
    scan_name = f"scan_{ datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S') }"
    
    load_dotenv()
    conf = Config.load("config/config.yaml")
    
    api_key = None
    if conf.interpretor.interpretor_type == "gpt":
        api_key = os.getenv("OPENAI_API_KEY")
    elif conf.interpretor.interpretor_type == "gemini":
        api_key = os.getenv("GOOGLE_API_KEY")

    scanner = NmapScanner()


    interpretor = InterpretorFactory.create_interpretor(
        conf.interpretor.interpretor_type,
        "Nmap Automator",
        conf.interpretor.model_flavor,
        api_key=api_key
    )
    interpretor.configure()
    target = conf.scanner.target #"www.megacorpone.com"
    save_dir = os.path.join(conf.scanner.save_dir, scan_name) #"results/"
    nmap_args = " ".join(conf.scanner.nmap_args)

    results = scanner.scan(target, nmap_args, save_dir)
    print("Interpreting with", conf.interpretor.interpretor_type, " via ", conf.interpretor.model_flavor)
    res = interpretor.interpret_with_suggestions(results, save_dir)
    print()
    print(res)

if __name__ == "__main__":
    main()