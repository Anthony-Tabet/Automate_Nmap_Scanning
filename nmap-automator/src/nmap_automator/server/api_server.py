from flask import Flask, request, jsonify
import os
import datetime
from dotenv import load_dotenv
from nmap_automator.interpretors import InterpretorFactory
from nmap_automator.scanner import NmapScanner
from nmap_automator.config_loader import Config
from nmap_automator.utils.api_utils import parse_request_data, read_results_from_csv

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
    
    def create_save_dir(self, conf: Config) -> str:
        scan_name = f"scan_{ datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S') }"
        return os.path.join(conf.scanner.save_dir, scan_name)

    def scan_with_nmap(self, conf: Config, save_dir: str) -> list[dict]:
        sav_dir = self.create_save_dir(conf)
        target = conf.scanner.target
        nmap_args = " ".join(conf.scanner.nmap_args)
        scanner = NmapScanner()
        return scanner.scan(target=target, arguments=nmap_args, save_dir=sav_dir)
    
    def run_llm_interpretation(self, conf: Config, results: list[dict], save_dir: str) -> list[dict]:
        interpretor = self._create_interpretor(conf)
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
        
        return res

    def process_scan(self, conf: Config):
        save_dir = self.create_save_dir(conf)
        nmap_results = self.scan_with_nmap(conf=conf, save_dir=save_dir)
        interpreter_results = self.run_llm_interpretation(conf=conf, results=nmap_results, save_dir=save_dir)
        return interpreter_results, nmap_results
    
def scan():
    """Combined operation: Nmap scan + LLM interpretation."""
    conf, error_response = parse_request_data()
    if error_response:
        return error_response

    try:
        runner = Runner()
        interpreted_results, raw_results = runner.process_scan(conf)
        return jsonify({
            "raw_results": raw_results,
            "interpreted_results": interpreted_results,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

def nmap_scan():
    """Run only the Nmap scan."""
    conf, error_response = parse_request_data()
    if error_response:
        return error_response

    try:
        runner = Runner()
        raw_results, save_dir = runner.scan_with_nmap(conf)
        file_path = os.path.join(save_dir, "initial_scan_results.csv")
        return jsonify({
            "raw_results": raw_results,
            "save_dir": save_dir,
            "file_path": file_path
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

def llm_interpret():
    """Run only the LLM interpretation on provided scan results."""
    data = dict(request.get_json())

    try:
        conf = Config.from_json(data)
        file_path = data.get("file_path")
        save_dir = data.get("save_dir", "./results")

        if not file_path:
            raise ValueError("Missing 'file_path' in request payload.")
        
        raw_results = read_results_from_csv(file_path)
    except Exception as e:
        return jsonify({"error": str(e)}), 400

    try:
        runner = Runner()
        interpreted_results = runner.run_llm_interpretation(conf, raw_results, save_dir)
        return jsonify({
            "interpreted_results": interpreted_results,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


def create_api_server() -> Flask:
    api_server = Flask(__name__)
    api_server.add_url_rule('/scan', 'scan', scan, methods=['POST'])
    api_server.add_url_rule('/nmap_scan', 'nmap_scan', nmap_scan, methods=['POST'])
    api_server.add_url_rule('/llm_interpret', 'llm_interpret', llm_interpret, methods=['POST'])
    return api_server