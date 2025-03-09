# Prepare GitHub repositories for Network Attack Simulator and Network Log Analyzer
# This script helps set up the initial repositories for both applications

# Network Attack Simulator Repository Setup
Write-Host "Setting up Network Attack Simulator repository..." -ForegroundColor Green

# Create .gitignore file for Network Attack Simulator
$simulator_gitignore = @"
# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
env/
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
*.egg-info/
.installed.cfg
*.egg

# Virtual Environment
venv/
ENV/
.env

# Streamlit
.streamlit/

# Logs
logs/
*.log

# OS specific
.DS_Store
Thumbs.db
"@

Set-Content -Path "c:\src\security-anomaly-dashboard\snapshots\v2.0-stable\.gitignore" -Value $simulator_gitignore

# Network Log Analyzer Repository Setup
Write-Host "Setting up Network Log Analyzer repository..." -ForegroundColor Green

# Create .gitignore file for Network Log Analyzer
$analyzer_gitignore = @"
# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
env/
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
*.egg-info/
.installed.cfg
*.egg

# Virtual Environment
venv/
ENV/
.env

# Streamlit
.streamlit/

# API Keys - IMPORTANT: Never commit API keys
.streamlit/secrets.toml

# Logs
logs/
*.log

# OS specific
.DS_Store
Thumbs.db
"@

Set-Content -Path "c:\src\security-anomaly-dashboard\snapshots\v2.0-stable\log-analyzer\.gitignore" -Value $analyzer_gitignore

# Create secrets.toml template for Log Analyzer
$secrets_template = @"
# Streamlit secrets file template
# Replace with your actual API keys before running locally
# For Streamlit Cloud deployment, add these as secrets in the dashboard

# Google Gemini API Key
GEMINI_API_KEY = "your_gemini_api_key_here"

# OpenAI API Key
OPENAI_API_KEY = "your_openai_api_key_here"
"@

# Create .streamlit directory
New-Item -Path "c:\src\security-anomaly-dashboard\snapshots\v2.0-stable\log-analyzer\.streamlit" -ItemType Directory -Force | Out-Null
Set-Content -Path "c:\src\security-anomaly-dashboard\snapshots\v2.0-stable\log-analyzer\.streamlit\secrets.toml.template" -Value $secrets_template

Write-Host "Repository preparation complete!" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "1. Create two GitHub repositories:" -ForegroundColor Yellow
Write-Host "   - network-attack-simulator" -ForegroundColor Cyan
Write-Host "   - network-log-analyzer" -ForegroundColor Cyan
Write-Host ""
Write-Host "2. For Network Attack Simulator:" -ForegroundColor Yellow
Write-Host "   cd c:\src\security-anomaly-dashboard\snapshots\v2.0-stable" -ForegroundColor Cyan
Write-Host "   git init" -ForegroundColor Cyan
Write-Host "   git add ." -ForegroundColor Cyan
Write-Host "   git commit -m 'Initial commit'" -ForegroundColor Cyan
Write-Host "   git remote add origin https://github.com/lhiebert01/network-attack-simulator.git" -ForegroundColor Cyan
Write-Host "   git push -u origin main" -ForegroundColor Cyan
Write-Host ""
Write-Host "3. For Network Log Analyzer:" -ForegroundColor Yellow
Write-Host "   cd c:\src\security-anomaly-dashboard\snapshots\v2.0-stable\log-analyzer" -ForegroundColor Cyan
Write-Host "   git init" -ForegroundColor Cyan
Write-Host "   git add ." -ForegroundColor Cyan
Write-Host "   git commit -m 'Initial commit'" -ForegroundColor Cyan
Write-Host "   git remote add origin https://github.com/lhiebert01/network-log-analyzer.git" -ForegroundColor Cyan
Write-Host "   git push -u origin main" -ForegroundColor Cyan
Write-Host ""
Write-Host "4. Deploy to Streamlit Cloud:" -ForegroundColor Yellow
Write-Host "   - Go to https://streamlit.io/cloud" -ForegroundColor Cyan
Write-Host "   - Sign in with your GitHub account" -ForegroundColor Cyan
Write-Host "   - Create a new app for each repository" -ForegroundColor Cyan
Write-Host "   - For the Log Analyzer, add your API keys as secrets in the Streamlit Cloud dashboard" -ForegroundColor Cyan
