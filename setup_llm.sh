#!/bin/bash
echo "Welcome Muhammad, Josh, Qasim, James, Syed Ali, and Junkai!"
ollama pull llama3.2:3b
ollama pull qwen2.5-coder:7b
echo "To set the LLM model before running the API, use: export LLM_MODEL=llama3.2:3b"
