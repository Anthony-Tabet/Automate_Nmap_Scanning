from flask import Flask, request, jsonify
import os
import datetime
from dotenv import load_dotenv
from nmap_automator.interpretors import InterpretorFactory
from nmap_automator.scanner import NmapScanner
from nmap_automator.config_loader import Config

api_server = Flask(__name__)

class Runner:
    def __init__(self):
        load_dotenv()

    def _create_interpretor(self, conf: Config):
        api_key = None
        if conf.interpretor.interpretor_type == "gpt":
            api_key = os.getenv("OPENAI_API_KEY")
        elif conf.interpretor.interpretor_type == "gemini":
            api_key = os.getenv("GOOGLE_API_KEY")

        interpretor = InterpretorFactory.create_interpretor(
          conf.interpretor.interpretor_type,
          "Nmap Automator",
          conf.interpretor.model_flavor,
          api_key=api_key
        )
        interpretor.configure()
        return interpretor

    def process_scan(self, conf: Config):
        scan_name = f"scan_{ datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S') }"
        target = conf.scanner.target
        save_dir = os.path.join(conf.scanner.save_dir, scan_name)
        nmap_args = " ".join(conf.scanner.nmap_args)
        
        scanner = NmapScanner()
        interpretor = self._create_interpretor(conf)

        results = scanner.scan(target, nmap_args, save_dir)
        print("Interpreting with", conf.interpretor.interpretor_type, " via ", conf.interpretor.model_flavor)
        
        runner_type = conf.interpretor.interpret_runner
        if runner_type == "normal":
            res = interpretor.interpret(results, save_dir)
        elif runner_type == "restricted":
            res = interpretor.interpret_restricted(results, save_dir)
        elif runner_type == "suggest":
            res = interpretor.interpret_with_suggestions(results, save_dir)
        else:
            raise Exception(f"Invalid interpret_runner: {runner_type}")

        return res, results
    
def scan():
    data = dict(request.get_json())

    try:
        conf = Config.from_json(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    
    try:
        runner = Runner()
        interpreted_results, raw_results = runner.process_scan(conf)
        return jsonify({
            "raw_results": raw_results,
            "interpreted_results": interpreted_results,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

def create_api_server() -> Flask:
    api_server = Flask(__name__)
    api_server.add_url_rule('/scan', 'scan', scan, methods=['POST'])
    return api_server