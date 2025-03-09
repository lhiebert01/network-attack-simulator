# Network Attack Simulator

A Streamlit-based educational tool for simulating and visualizing common network attacks.

## Features

- Simulate various network attacks (Port Scan, DoS, Brute Force, Data Exfiltration)
- Interactive dashboard with attack statistics and visualizations
- Detailed attack logs with filtering capabilities
- Educational explanations of attack types and detection methods
- Integration with Network Log Analyzer

## Deployment Instructions

### Local Development

1. Set up a Python virtual environment:
```bash
conda create -p venv python=3.12.9 -y
conda activate venv
pip install -r network-simulator-requirements.txt
```

2. Run the Streamlit app:
```bash
streamlit run streamlit_app.py
```

### Deployment to Streamlit Cloud

1. Create a GitHub repository:
```bash
git init
git add .
git commit -m "Initial commit"
git remote add origin https://github.com/yourusername/network-attack-simulator.git
git push -u origin main
```

2. Visit [Streamlit Cloud](https://streamlit.io/cloud) and sign in with your GitHub account.

3. Create a new app by selecting your repository and the `streamlit_app.py` file.

4. Configure the app settings and deploy.

## Integration with Network Log Analyzer

The Network Attack Simulator integrates with the Network Log Analyzer, which should be deployed as a separate Streamlit app. The "Open Log Analyzer" button in the sidebar will open the Log Analyzer in a new window.

## Requirements

See `network-simulator-requirements.txt` for the full list of dependencies.

## License

For educational purposes only. Do not use for malicious activities.

## Author

Created by [Your Name]
