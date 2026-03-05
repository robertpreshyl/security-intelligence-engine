#!/bin/bash
#
# AI-SOC Dashboard Launcher
# Starts both the FastAPI API server and Streamlit dashboard
#
# Usage: bash start_dashboard.sh
#        bash start_dashboard.sh --stop     # Kill running services
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# ── Stop command ──
if [ "$1" = "--stop" ] || [ "$1" = "stop" ]; then
    echo -e "${YELLOW}Stopping AI-SOC services...${NC}"
    fuser -k 8000/tcp 2>/dev/null && echo -e "${GREEN}  API server stopped${NC}" || echo "  API server not running"
    fuser -k 8501/tcp 2>/dev/null && echo -e "${GREEN}  Dashboard stopped${NC}" || echo "  Dashboard not running"
    exit 0
fi

echo -e "${CYAN}"
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║      AllysecLabs Security Intelligence Platform       ║"
echo "║      AI-Powered Threat Detection & Analysis          ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# ── Check virtual environment ──
if [ ! -d "venv" ]; then
    echo -e "${RED}Virtual environment not found.${NC}"
    echo "Run:  python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt"
    exit 1
fi
echo -e "${GREEN}[ok]${NC} Virtual environment found"

# ── Check dependencies ──
if ! ./venv/bin/python -c "import streamlit, fastapi, uvicorn, requests, pandas" 2>/dev/null; then
    echo -e "${YELLOW}Installing dependencies...${NC}"
    ./venv/bin/pip install -r requirements.txt -q
    echo -e "${GREEN}[ok]${NC} Dependencies installed"
else
    echo -e "${GREEN}[ok]${NC} Dependencies present"
fi

# ── Check .env ──
if [ ! -f ".env" ]; then
    echo -e "${RED}.env file not found.${NC}"
    echo "Run:  cp .env.example .env && nano .env"
    exit 1
fi

if ! grep -q "GROQ_API_KEY=gsk_" .env 2>/dev/null; then
    echo -e "${YELLOW}[warn]${NC} GROQ_API_KEY may not be set in .env — AI analysis will fail"
fi
echo -e "${GREEN}[ok]${NC} Configuration loaded"

# ── Kill any existing processes on our ports ──
if fuser 8000/tcp >/dev/null 2>&1; then
    echo -e "${YELLOW}Port 8000 in use — stopping old process...${NC}"
    fuser -k 8000/tcp 2>/dev/null
    sleep 1
fi

if fuser 8501/tcp >/dev/null 2>&1; then
    echo -e "${YELLOW}Port 8501 in use — stopping old process...${NC}"
    fuser -k 8501/tcp 2>/dev/null
    sleep 1
fi

# ── Create logs directory ──
mkdir -p logs

echo ""
echo -e "${BLUE}Starting services...${NC}"
echo ""

# ── Trap Ctrl+C ──
trap 'echo -e "\n${YELLOW}Stopping services...${NC}"; kill $API_PID $DASH_PID 2>/dev/null; exit 0' INT TERM

# ── Start API server (sg wazuh ensures alert file access without sudo) ──
echo -e "  [1/2] API Server..."
sg wazuh -c "./venv/bin/python api_server.py" > logs/api_server.log 2>&1 &
API_PID=$!

for i in {1..15}; do
    if curl -s http://localhost:8000/status > /dev/null 2>&1; then
        echo -e "        ${GREEN}[ok]${NC} API server ready (PID $API_PID)"
        break
    fi
    sleep 1
    if [ $i -eq 15 ]; then
        echo -e "        ${RED}[fail]${NC} API server did not start — check logs/api_server.log"
        kill $API_PID 2>/dev/null
        exit 1
    fi
done

# ── Start Streamlit dashboard ──
echo -e "  [2/2] Dashboard..."
./venv/bin/streamlit run dashboard.py \
    --server.port 8501 \
    --server.headless true \
    --server.address 0.0.0.0 \
    > logs/dashboard.log 2>&1 &
DASH_PID=$!

for i in {1..15}; do
    if curl -s http://localhost:8501 > /dev/null 2>&1; then
        echo -e "        ${GREEN}[ok]${NC} Dashboard ready (PID $DASH_PID)"
        break
    fi
    sleep 1
    if [ $i -eq 15 ]; then
        echo -e "        ${RED}[fail]${NC} Dashboard did not start — check logs/dashboard.log"
        kill $API_PID $DASH_PID 2>/dev/null
        exit 1
    fi
done

# ── Ready ──
echo ""
echo -e "${GREEN}╔═══════════════════════════════════════════════════════════╗"
echo -e "║                    READY                                  ║"
echo -e "╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  Dashboard:   ${CYAN}http://localhost:8501${NC}"
echo -e "  API Server:  ${CYAN}http://localhost:8000${NC}"
echo -e "  API Docs:    ${CYAN}http://localhost:8000/docs${NC}"
echo ""
echo -e "  Logs:  tail -f logs/api_server.log"
echo -e "         tail -f logs/dashboard.log"
echo ""
echo -e "  ${YELLOW}Press Ctrl+C to stop${NC}"
echo -e "  ${YELLOW}Or run: bash start_dashboard.sh --stop${NC}"
echo ""

# ── Wait ──
wait $API_PID $DASH_PID
