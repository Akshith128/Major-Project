"""The five AEGIS agents. Each takes the window state and returns its update.

Monitoring → Detection → Risk → Response → Governance

Agents only ever see `window["features"]`; ground-truth labels never reach
this module.
"""

import hashlib
import json
import time
from typing import Literal

from pydantic import BaseModel, Field, ValidationError

from . import config
from .family import GROUPS
from .llm import LLM_SOURCES, LLMUnavailable

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

SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

# MITRE ATT&CK techniques per attack family: a fixed table, so the mapping is
# auditable and can be scored, rather than generated free-form by the LLM.
ATTACK_TECHNIQUES = {
    "DDoS": ["T1498 Network Denial of Service", "T1499 Endpoint Denial of Service"],
    "DoS": ["T1499 Endpoint Denial of Service"],
    "Brute Force": ["T1110 Brute Force"],
    "Botnet": ["T1071 Application Layer Protocol (command and control)", "T1584.005 Botnet"],
    "Web Attack": ["T1190 Exploit Public-Facing Application"],
    "Infiltration": ["T1105 Ingress Tool Transfer", "T1046 Network Service Discovery"],
    "Port Scan": ["T1046 Network Service Discovery"],
    "Unknown": [],
}

# What each family typically looks like in CICFlowMeter window aggregates; given
# to the explaining agent as background knowledge.
FAMILY_GUIDE = """- DDoS: very many short, near-identical flows at high packet rates, often TCP SYN/ACK or UDP floods from many sources; little payload per flow.
- DoS: HTTP-layer floods from few sources (many short requests with PSH data, e.g. Hulk/GoldenEye) or slow attacks holding long, low-rate connections open.
- Brute Force: repeated short TCP sessions to one login service (SSH/FTP), similar small packet counts per flow, PSH-heavy, many resets as attempts fail.
- Botnet: periodic small command-and-control beacons from infected hosts; regular flow sizes and durations, low volume.
- Web Attack: few flows with larger HTTP request payloads (injection, XSS, login brute force over HTTP); rarely high volume.
- Infiltration: an internal host scanning or transferring tools after compromise; mixed protocols.
- Port Scan: many one- or two-packet flows, mostly resets or no response, almost no data."""

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


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _ask(llm, template: str, prompt: str, state, schema: type[BaseModel]):
    """Ask the LLM and validate its reply against `schema`.

    Returns (validated reply or None, provenance). Provenance records what is
    needed to reproduce the decision: template id, prompt and input hashes, the
    model version actually served, latency, tokens and whether the reply matched
    the schema. A reply that fails validation is treated like an outage, so the
    agent falls back to its rule-based path (which governance always escalates).
    """
    provenance = {
        "prompt_template": template,
        "prompt_sha256": _sha256(prompt),
        "input_sha256": _sha256(json.dumps(state["window"]["features"], sort_keys=True)),
        "model": getattr(llm, "model", None),
    }
    llm.last_meta = {}  # never let a previous call's metadata leak into this record
    started = time.perf_counter()
    try:
        raw = llm.ask_json(prompt, schema=schema.model_json_schema())
        reply = schema.model_validate(raw)
        provenance["schema_valid"] = True
        return reply, provenance
    except ValidationError as error:
        provenance["schema_valid"] = False
        provenance["error"] = f"Reply failed schema validation ({error.error_count()} error(s))."
        return None, provenance
    except LLMUnavailable as error:
        provenance["error"] = str(error)
        return None, provenance
    finally:
        provenance.update(getattr(llm, "last_meta", None) or {})
        provenance.setdefault("latency_ms", round((time.perf_counter() - started) * 1000))


# --- 1. Monitoring (deterministic triage) -----------------------------------

def monitoring_score(f: dict) -> float:
    """Homogeneity score in [0, 1]: attack traffic repeats one flow pattern."""
    if "unique_tcp_window_ratio" not in f:  # TCP-window ablation: reweight the other two terms
        return round((0.35 * f["dominant_signature_share"] + 0.20 * f["tcp_share"]) / 0.55, 3)
    low_diversity = 1 - min(f["unique_tcp_window_ratio"], 0.2) / 0.2
    return round(0.45 * low_diversity + 0.35 * f["dominant_signature_share"] + 0.20 * f["tcp_share"], 3)


def monitoring_agent(state) -> dict:
    f = state["window"]["features"]
    detector = state["window"].get("detector")
    if detector:  # hybrid: the benign-trained anomaly detector decides
        return {
            "monitoring": {
                "score": detector["score"],
                "suspicious": detector["anomalous"],
                "threshold": config.MONITORING_THRESHOLD,
                "signals": detector["deviations"] or ["No feature far from normal"],
                "method": detector["method"],
                "homogeneity_score": monitoring_score(f),
            },
            "trace": ["monitoring"],
        }
    score = monitoring_score(f)
    signals = []
    if f.get("unique_tcp_window_ratio", 1) <= 0.05:
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


# --- 2. Detection (reasoning model, rule fallback) --------------------------

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


class DetectionReply(BaseModel):
    threat: bool
    attack_type: Literal[tuple(ATTACK_TYPES)] | None = None
    confidence: int = Field(ge=0, le=100)
    reasoning: str = Field(min_length=1, max_length=1200)


class ExplanationReply(BaseModel):
    severity_hint: Literal[tuple(SEVERITIES)] | None = None
    explanation: str = Field(min_length=1, max_length=1200)


class ResponseReply(BaseModel):
    actions: list[str] = Field(min_length=1, max_length=4)
    rationale: str = Field(default="", max_length=600)


def _hybrid_detection(llm, state) -> dict:
    """The detector decided this is a threat and the incident memory named the family;
    the language model only explains it (it added errors when it chose the family)."""
    detector = state["window"]["detector"]
    vote = detector.get("family_vote")
    if vote:
        attack_type, neighbours = vote["family"], vote["neighbours"]
    else:  # no memory available: nearest similar incidents from the detector
        neighbours = detector["similar_incidents"]
        families = [n["family"] for n in neighbours[:3]]
        attack_type = max(set(families), key=families.count) if families else "Unknown"
    listed = "\n".join(
        f"- {n['family']} ({n.get('source', 'known incident')}, {n['day']}, distance {n['distance']})" for n in neighbours
    ) or "- none"
    prompt = f"""You are the detection agent in an autonomous network defence system.
A benign-trained anomaly detector flagged this window of {state['window']['features']['flows']} network flows as
abnormal (it looks less normal than {detector['confidence']}% of known-normal windows), and the incident memory
matched it to known incidents of the family: {attack_type}.
Do NOT change the family. Explain, for a security analyst, why this traffic fits {attack_type}, citing the features,
and say whether its impact deserves a higher severity than usual.

Traffic features (CICFlowMeter aggregates, no labels):
{_features_json(state)}

Features furthest from normal traffic:
{chr(10).join('- ' + d for d in detector['deviations']) or '- none stand out individually'}

Closest known incidents:
{listed}

How attack families usually look in these aggregates:
{FAMILY_GUIDE}

Reply with JSON only:
{{"severity_hint": one of {SEVERITIES} or null,
  "explanation": "two or three sentences citing the features"}}"""
    reply, provenance = _ask(llm, "explanation-v2", prompt, state, ExplanationReply)
    if reply is None:
        detection = {
            "reasoning": f"Anomaly detector: {', '.join(detector['deviations']) or 'abnormal feature mix'}. "
            f"Family from the closest known incidents ({vote['votes'] if vote else 'nearest'} agree).",
            "source": "anomaly",
            "note": provenance.get("error"),
        }
    else:
        detection = {"reasoning": reply.explanation.strip(), "severity_hint": reply.severity_hint, "source": "hybrid"}
    detection.update(
        threat=True,
        attack_type=attack_type,
        attack_group=GROUPS.get(attack_type, "Unknown"),
        family_vote=vote,
        confidence=detector["confidence"],
        decided_by=detector["method"],
        attack_techniques=ATTACK_TECHNIQUES.get(attack_type, []),
    )
    if llm.provider != "rules":
        detection["provenance"] = provenance
    return {"detection": detection, "trace": ["detection"]}


def make_detection_agent(llm):
    def detection_agent(state) -> dict:
        if state["window"].get("detector"):
            return _hybrid_detection(llm, state)
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
        reply, provenance = _ask(llm, "detection-v1", prompt, state, DetectionReply)
        if reply is None:
            detection = _rules_detection(state, provenance["error"])
        else:
            detection = {
                "threat": reply.threat,
                "attack_type": (reply.attack_type or "Unknown") if reply.threat else None,
                "confidence": reply.confidence,
                "reasoning": reply.reasoning.strip(),
                "source": llm.provider,
            }
        if llm.provider != "rules":
            detection["provenance"] = provenance
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
    severity = severity_for(risk)
    hint = d.get("severity_hint")
    # The reasoning model may raise severity, never lower it.
    if hint in SEVERITIES and SEVERITIES.index(hint) > SEVERITIES.index(severity):
        factors.append(f"Raised from {severity} to {hint} by the reasoning model (it can only raise)")
        severity = hint
    return {
        "risk": {"score": risk, "severity": severity, "factors": factors},
        "trace": ["risk"],
    }


# --- 4. Response (reasoning model, playbook fallback) -----------------------

def make_response_agent(llm):
    def response_agent(state) -> dict:
        d, r = state["detection"], state["risk"]
        attack_type = d["attack_type"] or "Unknown"
        playbook = PLAYBOOKS.get(attack_type, PLAYBOOKS["Unknown"])
        prompt = f"""You are the response agent in an autonomous network defence system.
Incident: {attack_type}, severity {r['severity']}, risk {r['score']}/100.
MITRE ATT&CK: {', '.join(d.get('attack_techniques') or ATTACK_TECHNIQUES.get(attack_type, [])) or 'not mapped'}.
Detector reasoning: {d['reasoning']}
Traffic features:
{_features_json(state)}

Standard playbook for {attack_type}: {playbook}

Recommend 2-4 concrete containment actions, most urgent first, adapted to these
features. Reply with JSON only:
{{"actions": ["..."], "rationale": "one sentence"}}"""
        reply, provenance = _ask(llm, "response-v1", prompt, state, ResponseReply)
        actions = [a.strip()[:300] for a in reply.actions if a.strip()] if reply else []
        if actions:
            response = {"actions": actions, "rationale": reply.rationale.strip(), "source": llm.provider}
        else:
            response = {
                "actions": playbook,
                "rationale": f"Standard {attack_type} playbook.",
                "source": "playbook",
                "note": provenance.get("error", "Reply contained no actions."),
            }
        if llm.provider != "rules":
            response["provenance"] = provenance
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
        if d["source"] not in (*LLM_SOURCES, "hybrid"):
            reasons.append(
                "No reasoning-model explanation (detector-only fallback)"
                if d["source"] == "anomaly"
                else "Decision came from rule fallback, not the reasoning model"
            )
        if reasons:
            decision = "PENDING_REVIEW"
        else:
            decision = "AUTO_APPROVED"
            reasons.append("Low-impact, high-confidence response within policy")
    return {
        "governance": {"decision": decision, "reasons": reasons, "policy": POLICY_VERSION},
        "trace": ["governance"],
    }
