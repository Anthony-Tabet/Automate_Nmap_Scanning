# Nmap Automator Project

This project provides a complete pipeline to enumerate subdomains, perform Nmap scans, and analyze results using LLM interpreters. The project consists of two main components:

1. **Server**: A Flask-based API for running Nmap scans and LLM analysis.
2. **Client**: A Streamlit app for interacting with the server and visualizing results.

---
## Demo

Here's a quick demo of the application in action:

[![Watch the Demo](https://testusjedu-my.sharepoint.com/:v:/g/personal/toufic_fakhry_usj_edu_lb/EaTnnETVpkJCgkI3wu3eh1gB_y5uBN89T5oqt0soNC1ezQ?nav=eyJyZWZlcnJhbEluZm8iOnsicmVmZXJyYWxBcHAiOiJTdHJlYW1XZWJBcHAiLCJyZWZlcnJhbFZpZXciOiJTaGFyZURpYWxvZy1MaW5rIiwicmVmZXJyYWxBcHBQbGF0Zm9ybSI6IldlYiIsInJlZmVycmFsTW9kZSI6InZpZXcifX0%3D&e=GydWhG)]

---

## Prerequisites

### Install `pipx`
If you do not already have `pipx` installed, install it using `pip`:

```bash
python -m pip install --user pipx
python -m pipx ensurepath
```

After installation, restart your terminal to make sure the `pipx` command is available.

---

## Project Setup

### Clone the Repository
Clone this repository to your local machine:

```bash
git clone <repository-url>
cd <repository-directory>
```

### Install Dependencies
This project uses `poetry` for dependency management. Install `poetry` with `pipx`:

```bash
pipx install poetry
```

#### Install Server Dependencies
Navigate to the `server` directory and install dependencies:

```bash
cd nmap-automator
poetry install
```

#### Install Client Dependencies
Navigate to the `client` directory and install dependencies:

```bash
cd ../automator-client
poetry install
```

---

## Running the Project

### Start the Server
Start the Flask server:

```bash
cd nmap-automator
poetry run nmap-automator
```
The server will start at `http://127.0.0.1:5000` by default.

### Start the Streamlit App
In a new terminal, start the Streamlit client:

```bash
cd ../automator-client
poetry run streamlit run src/app.py
```

This will launch the Streamlit app in your default web browser. By default, it runs on `http://localhost:8501`.

---

## Project Structure

```plaintext
<repository-directory>/
├── automation-client/                # Flask API for Nmap scans and LLM interpretation
│   ├── src/              # Server-side code
│   ├── tests/            # Tests for the server
│   └── pyproject.toml    # Poetry configuration for server
├── nmap-automator/                # Streamlit app for user interaction
│   ├── config/           # Default Config (template)  
│   ├── src/              # Contains the source code scripts + api
│   ├── tests/            # Tests for the client
│   └── pyproject.toml    # Poetry configuration for client
└── README.md              # Project documentation
```

---
## Setting up API keys

Create a .env file on the project root, then add the the following keys:

```code
OPENAI_API_KEY=".."

GOOGLE_API=".."
```
---

## Troubleshooting

### Common Errors

#### `ModuleNotFoundError`
Make sure all dependencies are installed using `poetry install` in both `server` and `client` directories.

#### Server Not Starting
Ensure you are in the `server` directory and have activated the environment:

```bash
cd server
poetry shell
flask run
```

#### Streamlit Not Starting
Ensure you are in the `client` directory and have activated the environment:

```bash
cd client
poetry shell
streamlit run app.py
```

### Additional Debugging
Check for any misconfigurations in the `pyproject.toml` files or `.env` files required by the project.

---

## Contribution Guidelines

1. Fork the repository and create a feature branch.
2. Submit a pull request with detailed descriptions of the changes made.

---

## License

This project is licensed under the AET License. See the `LICENSE` file for details.