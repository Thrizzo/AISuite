# AISuite — AI Enumeration Suite

OSAI Red Teaming tool for enumerating AI agent infrastructure.

## Phases
1. Network Scan — nmap or existing grepable output
2. Agent Discovery — /health on all Uvicorn services
3. Surface Mapping — endpoints, tools, purpose
4. Fingerprinting — model family identification
5. RAG Detection — 7-signal knowledge base mapping
6. Report — curl commands, findings, next steps

## Usage
```bash
python3 ai_suite.py -f nmap_results.txt -o results.json
python3 ai_suite.py -t 192.168.129.21-30 -o results.json
```

## Requirements
pip install requests --break-system-packages
