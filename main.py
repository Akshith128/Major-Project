from core.graph import build_graph


graph = build_graph()

initial_state = {
    "event_id": "EVT-001",
    "timestamp": "2026-09-21T19:00:00",
    "raw_data": {
        "source_ip": "192.168.1.50",
        "destination_ip": "10.0.0.5",
        "protocol": "TCP",
        "destination_port": 445,
        "packet_count": 850,
        "connection_count": 120
    },
    "monitoring_observations": [
        {
            "packet_count": 850,
            "connection_count": 120,
            "destination_port": 445
        },
        {
            "packet_count": 1500,
            "connection_count": 250,
            "destination_port": 445
        },
        {
            "packet_count": 2200,
            "connection_count": 400,
            "destination_port": 445
        }
    ],
    "status": "started"
}

result = graph.invoke(initial_state)

print("\n=== DETECTION RESULT ===")
print(result["detection_result"]["raw_response"])

print("\n=== ANALYSIS RESULT ===")
print(result["analysis_result"]["raw_response"])

print("\n=== CORRELATION RESULT ===")
print(result["correlation_result"]["raw_response"])

print("\n=== RISK RESULT ===")
print(result["risk_result"]["raw_response"])

print("\n=== SEVERITY ===")
print(result.get("severity"))

print("\n=== RISK SCORE ===")
print(result.get("risk_score"))

print("\n=== SEVERITY HISTORY ===")
for item in result.get("severity_history", []):
    print(item)

print("\n=== MONITORING RESULT ===")
print(result["monitoring_result"]["raw_response"])

print("\n=== RESPONSE RESULT ===")
if result.get("response_result"):
    print(result["response_result"]["raw_response"])
else:
    print("Response not triggered.")

print("\n=== VERIFICATION RESULT ===")
if result.get("verification_result"):
    print(result["verification_result"]["raw_response"])
else:
    print("Verification not triggered.")

print("\n=== FINAL STATUS ===")
print(result.get("status"))