# src/nmap_automator/runner.py
from nmap_automator.server import create_api_server


def main():
    app = create_api_server()
    app.run(host="127.0.0.1", port=5000, debug=True)

if __name__ == "__main__":
    main()