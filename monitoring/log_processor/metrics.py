"""Prometheus metrics for HoneyMind log processor."""
from prometheus_client import Counter, Gauge, Histogram, start_http_server

events_total = Counter(
    "honeymind_events_total",
    "Total honeypot events processed",
    ["service", "event_type", "attack_category"],
)

sessions_total = Counter(
    "honeymind_sessions_total",
    "Total honeypot sessions",
    ["service", "country_code", "verdict"],  # verdict = bot/human/unknown
)

auth_attempts_total = Counter(
    "honeymind_auth_attempts_total",
    "Authentication attempts",
    ["service", "username", "success"],
)

commands_total = Counter(
    "honeymind_commands_total",
    "Commands issued",
    ["service", "attack_category", "parser_action"],
)

llm_tokens_total = Counter(
    "honeymind_llm_tokens_total",
    "LLM tokens consumed",
    ["provider", "model_id", "token_type"],
)

llm_cost_total = Counter(
    "honeymind_llm_cost_total",
    "LLM cost in configured currency",
    ["provider", "model_id", "currency"],
)

unique_ips_gauge = Gauge(
    "honeymind_unique_ips",
    "Number of unique attacker IPs seen",
    ["service"],
)

active_sessions_gauge = Gauge(
    "honeymind_active_sessions",
    "Currently active sessions",
    ["service"],
)

sophistication_total = Counter(
    "honeymind_sophistication_total",
    "Attack sophistication distribution",
    ["profile_type"],  # script_kiddie / opportunist / targeted / nation_state
)

sophistication_score = Histogram(
    "honeymind_sophistication_score",
    "Attacker sophistication score (0-10)",
    buckets=[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
)

ai_trap_hits_total = Counter(
    "honeymind_ai_trap_hits_total",
    "AI trap triggers (LLM agents detected)",
    ["trap_id"],
)

hassh_detections_total = Counter(
    "honeymind_hassh_detections_total",
    "SSH client fingerprint (HASSH) detections",
    ["ssh_client"],
)

anonymization_type_total = Counter(
    "honeymind_anonymization_type_total",
    "Attacker anonymization method",
    ["anon_type"],
)

profile_type_total = Counter(
    "honeymind_profile_type_total",
    "Attacker profile distribution",
    ["profile_type"],  # script_kiddie / opportunist / targeted / nation_state
)

tool_detections_total = Counter(
    "honeymind_tool_detections_total",
    "Detected attacker tools",
    ["tool"],
)

country_events_total = Counter(
    "honeymind_country_events_total",
    "Events by country",
    ["country_code", "country"],
)

inter_command_delay_ms = Histogram(
    "honeymind_inter_command_delay_ms",
    "Time between commands in a session (ms)",
    buckets=[50, 100, 200, 500, 1000, 2000, 5000, 10000, 30000, 60000],
)

# Ecological metrics
llm_co2_grams_total = Counter(
    "honeymind_llm_co2_grams_total",
    "Estimated CO2 equivalent in grams from LLM token usage",
    ["provider", "model_id"],
)

llm_energy_wh_total = Counter(
    "honeymind_llm_energy_wh_total",
    "Estimated energy consumption in Wh from LLM token usage",
    ["provider", "model_id"],
)

attack_phase_transitions_total = Counter(
    "honeymind_attack_phase_transitions_total",
    "Observed attack phase transitions",
    ["from_phase", "to_phase"],
)

files_accessed_total = Counter(
    "honeymind_files_accessed_total",
    "Files accessed or attempted by attackers",
    ["file_path", "attack_category"],
)


def start_metrics_server(port: int = 9090) -> None:
    start_http_server(port)
