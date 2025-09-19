# stressed.py

import os
from datetime import datetime
from enum import Enum
from typing import List, Literal, Optional

import outlines
import pydantic
from pydantic import BaseModel, Field
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

# --- Pydantic Schemas for Structured Output ---

class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class AttackType(str, Enum):
    BRUTE_FORCE = "BRUTE_FORCE"
    SQL_INJECTION = "SQL_INJECTION"
    XSS = "XSS"
    FILE_INCLUSION = "FILE_INCLUSION"
    COMMAND_INJECTION = "COMMAND_INJECTION"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    UNKNOWN = "UNKNOWN"

class WebTrafficPattern(BaseModel):
    url_path: str = Field(..., description="The URL path pattern observed.")
    http_method: str = Field(..., description="The HTTP method used (e.g., GET, POST).")
    hits_count: int = Field(..., description="Number of times this pattern was hit.")
    response_codes: dict[str, int] = Field(..., description="A map of HTTP status codes to their counts for this pattern.")

class LogID(BaseModel):
    log_id: str = Field(
        description="The ID of the log entry, like 'LOGID-AB'.",
        pattern=r"LOGID-([A-Z]+)",
    )

    def find_in(self, logs: List[str]) -> Optional[str]:
        for log in logs:
            if self.log_id in log:
                return log
        return None

class IPAddress(BaseModel):
    ip_address: str = Field(pattern=r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

class ResponseCode(BaseModel):
    response_code: str = Field(pattern=r"^\d{3}$")

class WebSecurityEvent(BaseModel):
    relevant_log_entry_ids: List[LogID] = Field(..., description="List of log IDs related to this event.")
    reasoning: str = Field(..., description="Detailed reasoning for flagging this event.")
    event_type: str = Field(..., description="A short, descriptive title for the event.")
    severity: SeverityLevel
    confidence_score: float = Field(..., ge=0.0, le=1.0, description="Confidence score from 0.0 to 1.0.")
    url_pattern: str = Field(..., description="URL pattern that triggered the event.")
    http_method: Literal["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "TRACE", "CONNECT"]
    source_ips: List[IPAddress]
    response_codes: List[ResponseCode]
    possible_attack_patterns: List[AttackType]
    recommended_actions: List[str] = Field(..., description="A list of concrete, actionable steps to take.")

class LogAnalysis(BaseModel):
    summary: str = Field(..., description="A high-level, natural language summary of the logs.")
    observations: List[str] = Field(..., description="A list of key, neutral observations from the logs.")
    events: List[WebSecurityEvent] = Field(..., description="A list of potential security events found.")
    traffic_patterns: List[WebTrafficPattern] = Field(..., description="A list of common traffic patterns.")
    highest_severity: Optional[SeverityLevel]
    requires_immediate_attention: bool = Field(..., description="True if a human should review this immediately.")


# --- Main STRESSED Class ---

class STRESSED:
    def __init__(self, model, tokenizer, log_type: str, prompt_template_path: str):
        if not os.path.exists(prompt_template_path):
            raise FileNotFoundError(f"Prompt template not found: {prompt_template_path}")

        self.model = model
        self.tokenizer = tokenizer
        self.log_type = log_type
        with open(prompt_template_path, "r") as file:
            self.prompt_template = file.read()

        # Initialize the JSON generator with our Pydantic schema
        from outlines.generator import Generator
        from outlines.generator import JsonSchema
        self.generator = Generator(self.model, JsonSchema(LogAnalysis))

    def _to_prompt(self, logs_text: str) -> str:
        # Fills the prompt template
        prompt = self.prompt_template.format(
            log_type=self.log_type,
            stress_prompt="",  # Empty stress prompt for now
            logs=logs_text,
            model_schema=LogAnalysis.model_json_schema()
        )
        return prompt

    def analyze_logs(self, logs: List[str], chunk_size: int = 20, format_output: bool = True) -> List[LogAnalysis]:
        results = []
        for i in range(0, len(logs), chunk_size):
            chunked_logs = [log.strip() for log in logs[i:i + chunk_size] if log.strip()]
            if not chunked_logs:
                continue

            # Create unique, temporary IDs for this chunk so the LLM can reference specific lines
            log_ids = [f"LOGID-{chr(65 + j)}" for j in range(len(chunked_logs))]
            logs_with_ids = [f"{log_id} {log}" for log_id, log in zip(log_ids, chunked_logs)]
            chunk_text = "\n".join(logs_with_ids)

            print(f"\n--- Analyzing Log Chunk {i // chunk_size + 1} ---")
            prompt = self._to_prompt(chunk_text)
            print(f"Prompt length: {len(prompt)} characters")
            try:
                analysis_raw = self.generator(prompt, max_new_tokens=512)
                print(f"Analysis type: {type(analysis_raw)}")
                print(f"Analysis content: {analysis_raw}")
                
                # Parse the JSON string if it's a string
                if isinstance(analysis_raw, str):
                    import json
                    import re
                    try:
                        # Try to clean up the JSON string
                        json_str = analysis_raw.strip()
                        
                        # Remove any text before the first { and after the last }
                        start_idx = json_str.find('{')
                        end_idx = json_str.rfind('}')
                        if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
                            json_str = json_str[start_idx:end_idx+1]
                        
                        # Try to fix common JSON issues
                        json_str = re.sub(r',\s*}', '}', json_str)  # Remove trailing commas before }
                        json_str = re.sub(r',\s*]', ']', json_str)  # Remove trailing commas before ]
                        
                        analysis_dict = json.loads(json_str)
                        analysis = LogAnalysis(**analysis_dict)
                    except (json.JSONDecodeError, TypeError) as e:
                        print(f"Error parsing JSON: {e}")
                        print(f"Raw response: {analysis_raw[:500]}...")
                        # Create a fallback analysis with actual log content
                        analysis = LogAnalysis(
                            summary=f"JSON parsing error, but logs were processed. Raw response: {str(e)[:100]}",
                            observations=[],
                            events=[],
                            traffic_patterns=[],
                            highest_severity=None,
                            requires_immediate_attention=False
                        )
                else:
                    analysis = analysis_raw
                
                results.append(analysis)
            except Exception as e:
                print(f"Error analyzing chunk: {e}")
                # Create a fallback analysis
                fallback = LogAnalysis(
                    summary=f"Error analyzing chunk {i // chunk_size + 1}: {str(e)}",
                    observations=[],
                    events=[],
                    traffic_patterns=[],
                    highest_severity=None,
                    requires_immediate_attention=False
                )
                results.append(fallback)
                analysis = fallback

            if format_output:
                format_log_analysis(analysis, logs_with_ids)
        return results

# --- Formatting and Reporting ---
def format_log_analysis(analysis: LogAnalysis, logs: List[str]):
    # This function creates the pretty, human-readable terminal output
    console = Console()
    header = Panel(f"[bold yellow]Log Analysis Report[/]\n[blue]{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/]", border_style="yellow")

    summary_text = f"[bold white]Summary:[/]\n[cyan]{analysis.summary}[/]\n\n"
    if analysis.highest_severity:
        summary_text += f"[bold red]Highest Severity: {analysis.highest_severity.value}[/]\n"
    summary_text += f"[bold {'red' if analysis.requires_immediate_attention else 'green'}]Requires Immediate Attention: {analysis.requires_immediate_attention}[/]"
    summary_panel = Panel(summary_text, border_style="blue", title="📝 Analysis Summary")
    
    console.print(header)
    console.print(summary_panel)

    if analysis.events:
        console.print("\n[bold red]⚠️  Security Events:[/]")
        for event in analysis.events:
            event_table = Table(show_header=False, box=None, padding=0, show_edge=False)
            event_table.add_column()
            event_table.add_row(f"[bold magenta]Event Type:[/bold magenta] {event.event_type}")
            event_table.add_row(f"[bold magenta]Severity:[/bold magenta] {event.severity.value}")
            event_table.add_row(f"[bold magenta]Confidence:[/bold magenta] {event.confidence_score * 100:.0f}%")
            event_table.add_row(f"[bold magenta]Reasoning:[/bold magenta] {event.reasoning}")
            event_table.add_row(f"[bold magenta]Source IPs:[/bold magenta] {', '.join([ip.ip_address for ip in event.source_ips])}")
            event_table.add_row(f"[bold magenta]URL Pattern:[/bold magenta] {event.url_pattern}")
            
            # Find and display the actual log lines
            related_logs = [log_id.find_in(logs) for log_id in event.relevant_log_entry_ids]
            log_text = "\n".join([log for log in related_logs if log])
            
            event_panel = Panel(event_table, border_style="red", title=f"Event: {event.event_type}")
            console.print(event_panel)
            if log_text:
                console.print(Panel(log_text, border_style="cyan", title="Related Log Entries"))