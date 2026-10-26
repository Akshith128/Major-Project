"""The five AEGIS agents. Each takes the window state and returns its update.

Monitoring → Detection → Risk → Response → Governance

Agents only ever see `window["features"]`; ground-truth labels never reach
this module.
"""

import json

from . import config
from .llm import LLMUnavailable

ATTACK_TYPES = [
    "DDoS",
    "DoS",
    "Brute Force",
    "Botnet",
    "Web Attack",
    "Infiltration",
    "Port Scan",
    "Unknown",
]

IMPACT = {
    "DDoS": 1.0,
    "DoS": 0.95,
    "Infiltration": 1.0,
    "Botnet": 0.95,
    "Web Attack": 0.9,
    "Brute Force": 0.85,
    "Port Scan": 0.7,
    "Unknown": 0.8,
}

PLAYBOOKS = {
    "DDoS": [
        "Enable upstream rate limiting and SYN cookies on the targeted service",
        "Divert the affected prefix to DDoS scrubbing",
        "Alert the network operations on-call",
    ],
    "DoS": [
        "Rate-limit and time out slow or half-open connections to the service",
        "Block the offending source addresses at the edge firewall",
        "Scale out or restart the degraded service",
    ],
    "Brute Force": [
        "Lock the targeted accounts and enforce MFA",
        "Block the source addresses for the authentication service",
        "Review authentication logs for successful logins",
    ],
    "Botnet": [
        "Isolate the infected hosts from the network",
        "Sinkhole the command-and-control destinations at DNS and the firewall",
        "Collect forensic images before reimaging",
    ],
    "Web Attack": [
        "Enable WAF blocking rules for the targeted web application",
        "Block the source addresses and review application logs",
        "Patch or harden the vulnerable endpoint",
    ],
    "Infiltration": [
        "Isolate the internal host showing the suspicious traffic",
        "Reset credentials used from that host",
        "Start a full incident investigation",
    ],
    "Port Scan": [
        "Block the scanning source at the perimeter",
        "Verify no unexpected services are exposed",
    ],
    "Unknown": [
        "Capture packets for the affected flows",
        "Escalate to a security analyst for triage",
    ],
}


def _features_json(state) -> str:
    return json.dumps(state["window"]["features"], indent=2)


# --- 1. Monitoring (deterministic triage) -----------------------------------

def monitoring_score(f: dict) -> float:
    """Homogeneity score in [0, 1]: attack traffic repeats one flow pattern."""
    low_diversity = 1 - min(f["unique_tcp_window_ratio"], 0.2) / 0.2
    return round(0.45 * low_diversity + 0.35 * f["dominant_signature_share"] + 0.20 * f["tcp_share"], 3)


def monitoring_agent(state) -> dict:
    f = state["window"]["features"]
    score = monitoring_score(f)
    signals = []
    if f["unique_tcp_window_ratio"] <= 0.05:
        signals.append("Very low TCP window diversity across flows")
    if f["dominant_signature_share"] >= 0.5:
        signals.append(f"{f['dominant_signature_share']:.0%} of flows share one signature")
    if f["tcp_share"] >= 0.99:
        signals.append("TCP-only traffic")
    if f["rst_share"] >= 0.5:
        signals.append(f"{f['rst_share']:.0%} of flows reset")
    if f["no_response_share"] >= 0.5:
        signals.append(f"{f['no_response_share']:.0%} of flows got no response")
    return {
        "monitoring": {
            "score": score,
            "suspicious": score >= config.MONITORING_THRESHOLD,
            "threshold": config.MONITORING_THRESHOLD,
            "signals": signals,
        },
        "trace": ["monitoring"],
    }


# --- 2. Detection (Gemini, rule fallback) -----------------------------------

def _rules_detection(state, note: str) -> dict:
    score = state["monitoring"]["score"]
    threat = score >= config.RULES_DETECTION_THRESHOLD
    return {
        "threat": threat,
        "attack_type": "Unknown" if threat else None,
        "confidence": round(score * 100),
        "reasoning": (
            f"Rule-based: monitoring score {score} "
            f"{'≥' if threat else '<'} {config.RULES_DETECTION_THRESHOLD}."
        ),
        "source": "rules",
        "note": note,
    }


def make_detection_agent(llm):
    def detection_agent(state) -> dict:
        prompt = f"""You are the detection agent in an autonomous network defence system.
Decide whether this window of {state['window']['features']['flows']} network flows
(CICFlowMeter aggregates, no labels) is malicious.

Traffic features:
{_features_json(state)}

Monitoring signals: {state['monitoring']['signals']} (score {state['monitoring']['score']})

Reply with JSON only:
{{"threat": true|false,
  "attack_type": one of {ATTACK_TYPES} or null when no threat,
  "confidence": integer 0-100,
  "reasoning": "one or two sentences citing the features"}}"""
        try:
            out = llm.ask_json(prompt)
            threat = bool(out.get("threat"))
            attack_type = out.get("attack_type")
            detection = {
                "threat": threat,
                "attack_type": (attack_type if attack_type in ATTACK_TYPES else "Unknown") if threat else None,
                "confidence": max(0, min(100, int(out.get("confidence", 0)))),
                "reasoning": str(out.get("reasoning", "")).strip(),
                "source": llm.provider,
            }
        except (LLMUnavailable, ValueError, TypeError) as error:
            detection = _rules_detection(state, str(error))
        return {"detection": detection, "trace": ["detection"]}

    return detection_agent


# --- 3. Risk (deterministic, correlated with earlier incidents) -------------

def severity_for(risk: float) -> str:
    if risk >= 80:
        return "CRITICAL"
    if risk >= 60:
        return "HIGH"
    if risk >= 40:
        return "MEDIUM"
    return "LOW"


def risk_agent(state) -> dict:
    d = state["detection"]
    attack_type = d["attack_type"] or "Unknown"
    base = 0.6 * d["confidence"] + 40 * state["monitoring"]["score"]
    impact = IMPACT.get(attack_type, 0.8)
    repeats = state.get("context", {}).get("prior_incidents", {}).get(attack_type, 0)
    correlation_bonus = min(15, 5 * repeats)
    risk = round(min(100.0, base * impact + correlation_bonus), 1)
    factors = [
        f"Detector confidence {d['confidence']}",
        f"Monitoring score {state['monitoring']['score']}",
        f"{attack_type} impact weight {impact}",
    ]
    if repeats:
        factors.append(f"Correlated with {repeats} earlier {attack_type} incident(s) in this run (+{correlation_bonus})")
    return {
        "risk": {"score": risk, "severity": severity_for(risk), "factors": factors},
        "trace": ["risk"],
    }


# --- 4. Response (Gemini, playbook fallback) --------------------------------

def make_response_agent(llm):
    def response_agent(state) -> dict:
        d, r = state["detection"], state["risk"]
        attack_type = d["attack_type"] or "Unknown"
        playbook = PLAYBOOKS.get(attack_type, PLAYBOOKS["Unknown"])
        prompt = f"""You are the response agent in an autonomous network defence system.
Incident: {attack_type}, severity {r['severity']}, risk {r['score']}/100.
Detector reasoning: {d['reasoning']}
Traffic features:
{_features_json(state)}

Standard playbook for {attack_type}: {playbook}

Recommend 2-4 concrete containment actions, most urgent first, adapted to these
features. Reply with JSON only:
{{"actions": ["..."], "rationale": "one sentence"}}"""
        try:
            out = llm.ask_json(prompt)
            actions = [str(a).strip() for a in out.get("actions", []) if str(a).strip()][:4]
            if not actions:
                raise LLMUnavailable("Gemini returned no actions.")
            response = {
                "actions": actions,
                "rationale": str(out.get("rationale", "")).strip(),
                "source": llm.provider,
            }
        except (LLMUnavailable, ValueError, TypeError) as error:
            response = {
                "actions": playbook,
                "rationale": f"Standard {attack_type} playbook.",
                "source": "playbook",
                "note": str(error),
            }
        response["execution"] = "RECOMMENDED_NOT_EXECUTED"
        return {"response": response, "trace": ["response"]}

    return response_agent


# --- 5. Governance (policy + human-in-the-loop) -----------------------------

POLICY_VERSION = "AEGIS-GOV-1"


def governance_agent(state) -> dict:
    d = state.get("detection")
    if not state["monitoring"]["suspicious"]:
        decision, reasons = "NO_ACTION", ["Monitoring score below threshold; detector not invoked"]
    elif not d["threat"]:
        decision, reasons = "NO_ACTION", ["Detection agent found no threat"]
    else:
        severity = state["risk"]["severity"]
        reasons = []
        if severity in ("HIGH", "CRITICAL"):
            reasons.append(f"{severity} severity requires analyst approval")
        if d["confidence"] < config.AUTO_APPROVE_MIN_CONFIDENCE:
            reasons.append(f"Detector confidence {d['confidence']} < {config.AUTO_APPROVE_MIN_CONFIDENCE}")
        if d["source"] != "gemini":
            reasons.append("Decision came from rule fallback, not the reasoning model")
        if reasons:
            decision = "PENDING_REVIEW"
        else:
            decision = "AUTO_APPROVED"
            reasons.append("Low-impact, high-confidence response within policy")
    return {
        "governance": {"decision": decision, "reasons": reasons, "policy": POLICY_VERSION},
        "trace": ["governance"],
    }
