#!/bin/bash
source .venv/bin/activate
cd central
uv sync
python3 main.py
