import csv
from flask import jsonify, request
from nmap_automator.config_loader.config import Config

def parse_request_data():
    """
    Utility function to parse request data into a Config object.
    Returns:
        - Config object on success.
        - JSON response with 400 status code on error.
    """
    try:
        data = dict(request.get_json())
        conf = Config.from_json(data)
        return conf, None
    except Exception as e:
        return None, jsonify({"error": str(e)}), 400

def read_results_from_csv(file_path):
    """Read scan results from a CSV file."""
    try:
        with open(file_path, "r") as csv_file:
            reader = csv.DictReader(csv_file)
            return [row for row in reader]
    except FileNotFoundError:
        raise ValueError(f"File not found: {file_path}")
    except Exception as e:
        raise ValueError(f"Error reading file {file_path}: {e}")