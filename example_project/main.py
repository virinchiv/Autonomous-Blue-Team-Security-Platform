# main.py

import torch
import outlines
from transformers import AutoTokenizer
from mystressed import STRESSED

# --- Model and Device Configuration (Mac Friendly) ---
model_name = "EleutherAI/gpt-neo-1.3B" # A larger model that should handle longer contexts
log_type = "web server"
prompt_template_path = "security-prompt.txt"

# Auto-detect the best device for Mac (MPS for Apple Silicon, CPU for Intel)
if torch.backends.mps.is_available():
    device = "mps"
    # Use float16 for better performance on Apple Silicon
    dtype = torch.float16
else:
    device = "cpu"
    # Use bfloat16 if available on CPU, otherwise default
    dtype = torch.bfloat16 if torch.cpu.is_bf16_supported() else torch.float32

print(f"Using device: {device}")
print(f"Using dtype: {dtype}")

# Load the model and tokenizer using transformers
from transformers import AutoModelForCausalLM

model = AutoModelForCausalLM.from_pretrained(
    model_name,
    device_map="auto" if device == "mps" else device,
    torch_dtype=dtype,
)

tokenizer = AutoTokenizer.from_pretrained(model_name)

# Wrap with outlines
model = outlines.from_transformers(model, tokenizer)

# --- Initialize and Run the Parser ---

# Initialize our log analyzer
parser = STRESSED(
    model=model,
    tokenizer=tokenizer,
    log_type=log_type,
    prompt_template_path=prompt_template_path
)

# Place your log file in the 'logs' directory
log_path = "logs/access-10k.log" 

# Load the logs into memory
try:
    with open(log_path, "r") as file:
        logs = file.readlines()[:10]  # Limit to first 10 lines for testing
except FileNotFoundError:
    print(f"Error: Log file not found at '{log_path}'")
    print("Please make sure you have a 'logs' folder with the log file inside.")
    exit()

# Start the analysis!
results = parser.analyze_logs(
    logs,
    chunk_size=1,      # How many lines to analyze at once (minimized for token limits).
    format_output=True # Set to True to print pretty reports
)

print("\n\n✅ Analysis Complete.")
# The 'results' variable holds a list of LogAnalysis objects you can use programmatically
# For example, let's find all critical events:
critical_events = [
    event for analysis in results 
    for event in analysis.events 
    if event.severity == "CRITICAL"
]

if critical_events:
    print(f"Found {len(critical_events)} CRITICAL events requiring immediate attention!")