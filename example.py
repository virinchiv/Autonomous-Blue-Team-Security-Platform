import os
os.environ["TOKENIZERS_PARALLELISM"] = "false"

import outlines
import torch
import time
import logging
from transformers import AutoTokenizer, AutoModelForCausalLM
from stressed import STRESSED  # Our anxious little helper

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# The model we're using - using a smaller, faster model for testing
# model_name = "microsoft/DialoGPT-medium"  # Much faster for testing
model_name = "Qwen/Qwen2.5-Coder-7B-Instruct"  # Better for structured generation

# The type of logs we're parsing. You don't have to use this, but it's
# helpful for the model to understand the context of the logs.
log_type = "web server"

# The path to the prompt template we're using. This should be a file in
# the repo.
prompt_template_path = "security-prompt.txt"

# Load the model
logger.info(f"Loading model: {model_name}")
start_time = time.time()

hf_model = AutoModelForCausalLM.from_pretrained(
    model_name,
    device_map="cpu",  # Force CPU to avoid MPS issues
    use_cache=True,
    torch_dtype=torch.float32,  # Use float32 for CPU
    low_cpu_mem_usage=True,
)
hf_tokenizer = AutoTokenizer.from_pretrained(model_name)

# Add padding token if it doesn't exist
if hf_tokenizer.pad_token is None:
    hf_tokenizer.pad_token = hf_tokenizer.eos_token

load_time = time.time() - start_time
logger.info(f"Model loaded in {load_time:.2f} seconds")

logger.info("Initializing outlines model...")
model = outlines.from_transformers(hf_model, hf_tokenizer)
# Load the tokenizer
tokenizer = hf_tokenizer
logger.info("Model initialization complete!")

# Initialize our anxious intern!
logger.info("Initializing STRESSED parser...")
parser = STRESSED(
    model=model,
    tokenizer=tokenizer,
    log_type=log_type,
    prompt_template_path=prompt_template_path,
    token_max=2048,  # Increased for better analysis
    stressed_out=True  # Make the intern more anxious
)
logger.info("STRESSED parser ready!")

# Load the logs you want to parse. There's three example logs you can
# use in the repo.
test_logs = [
    # Access log for an e-commerce site's web server (smaller for testing)
    "logs/access-250.log",
    # Access log for an e-commerce site's web server (full)
    "logs/access-10k.log",
    # Linux system log
    "logs/linux-2k.log",
    # Apache access log
    "logs/apache-2k.log"
]

# Choose the access log for giggles
log_path = test_logs[0]
logger.info(f"Loading logs from: {log_path}")

# Load the logs into memory
try:
    with open(log_path, "r") as file:
        logs = file.readlines()
    logger.info(f"Loaded {len(logs)} log entries")
except FileNotFoundError:
    logger.error(f"Log file not found: {log_path}")
    exit(1)

# Start the analysis
logger.info("Starting log analysis...")
start_analysis = time.time()

results = parser.analyze_logs(
    logs,

    # Chunk the logs into smaller chunks for faster testing.
    chunk_size=10,  # Balanced chunk size for analysis

    # Format output prints a helpful display in your terminal.
    format_output=True
)

analysis_time = time.time() - start_analysis
logger.info(f"Analysis completed in {analysis_time:.2f} seconds")

# You can do stuff with the results here. results is a list of LogAnalysis objects.
logger.info(f"Processing {len(results)} analysis results...")
for i, analysis in enumerate(results):
    logger.info(f"Result {i+1}/{len(results)}:")
    print(f"\n=== ANALYSIS RESULT {i+1} ===")
    print(analysis.summary)
    if analysis.events:
        print(f"Found {len(analysis.events)} security events")
    if analysis.traffic_patterns:
        print(f"Found {len(analysis.traffic_patterns)} traffic patterns")

logger.info("All analysis complete!")
