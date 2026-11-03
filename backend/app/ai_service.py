import os
import json
import urllib.request
import urllib.error

def get_template_explanation(attack_type, source_ip, destination_ip):
    """Fallback generator providing high-quality contextual sentences without an API key."""
    norm_type = (attack_type or '').strip().lower()
    
    if 'ddos' in norm_type or 'dos' in norm_type:
        return (
            f"A massive flood of automated network traffic is coming from source IP {source_ip} targeting {destination_ip}, "
            f"attempting to exhaust server bandwidth and make digital services unavailable for legitimate users."
        )
    elif 'brute' in norm_type or 'patator' in norm_type:
        return (
            f"An unusually high rate of repeated connection attempts was detected from {source_ip} targeting {destination_ip}, "
            f"indicating an active credential-stuffing or dictionary attack attempting to compromise system authentication."
        )
    elif 'port' in norm_type or 'scan' in norm_type:
        return (
            f"Host {source_ip} is probing multiple network ports on {destination_ip} in rapid succession, "
            f"attempting to discover open service listeners and identify vulnerable entry points for a breach."
        )
    elif 'bot' in norm_type:
        return (
            f"Suspicious coordinated beaconing patterns from {source_ip} indicate zombie botnet infection communicating "
            f"with command-and-control infrastructure against host {destination_ip}."
        )
    elif 'web' in norm_type or 'sql' in norm_type or 'xss' in norm_type:
        return (
            f"Malicious web application payloads (SQL injection, XSS, or path traversal) were detected from {source_ip} "
            f"targeting application endpoints on {destination_ip}."
        )
    elif 'recon' in norm_type or 'probe' in norm_type:
        return (
            f"Anomalous reconnaissance scanning was detected originating from {source_ip}, "
            f"attempting to map internal network subnets and footprint target infrastructure on {destination_ip}."
        )
    elif 'malware' in norm_type or 'trojan' in norm_type:
        return (
            f"Suspicious host-to-host network metrics indicate a potential malware execution or lateral movement attempt "
            f"originating from {source_ip} targeting system {destination_ip}."
        )
    elif 'benign' in norm_type or 'normal' in norm_type:
        return (
            f"Benign traffic flow verified between internal host {source_ip} and destination {destination_ip}, "
            f"matching authorized operational security baselines."
        )
    else:
        return f"Suspicious network anomaly classified as {attack_type} was detected from {source_ip} targeting {destination_ip}."

def generate_threat_explanation(threat):
    """
    Generate a one-sentence plain English explanation for a threat.
    Queries Gemini 1.5 Flash if GEMINI_API_KEY is present, else falls back to templates.
    """
    api_key = os.getenv("GEMINI_API_KEY")
    
    if not api_key:
        print("GEMINI_API_KEY not configured. Falling back to local explanation template.")
        return get_template_explanation(threat.attack_type, threat.source_ip, threat.destination_ip)
        
    print("GEMINI_API_KEY configured. Requesting live AI explanation from Google Gemini...")
    
    # Construct a contextual prompt
    features_summary = ""
    if threat.features:
        feat = threat.features
        duration = feat.get('flow_duration', feat.get('duration', 0))
        pkts = feat.get('tot_fwd_pkts', feat.get('count', 0))
        rate = feat.get('flow_byts_s', feat.get('packet_size', 0))
        syn = feat.get('syn_flag_cnt', feat.get('serror_rate', 0))
        port = feat.get('port', 'N/A')
        proto = feat.get('protocol', 'TCP')
        features_summary = f"Port: {port}, Protocol: {proto}, Flow Duration: {duration}us, Fwd Packets: {pkts}, Bytes/sec: {rate}, SYN Flags: {syn}"
        
    prompt = (
        f"Explain in exactly one plain-English sentence what this network security alert means and why it is concerning, "
        f"without using complex technical jargon. Focus on the business impact of this activity. "
        f"Alert details:\n"
        f"- Threat Type: {threat.attack_type}\n"
        f"- Source IP Address: {threat.source_ip}\n"
        f"- Destination IP Address: {threat.destination_ip}\n"
        f"- Severity Rating: {threat.severity}\n"
        f"- AI Model Confidence: {threat.confidence}\n"
        f"- Traffic Metrics: {features_summary}\n\n"
        f"Response MUST be a single, clear, actionable sentence under 40 words."
    )
    
    # Prepare Gemini API request payload
    url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent"
    payload = {
        "contents": [{
            "parts": [{
                "text": prompt
            }]
        }],
        "generationConfig": {
            "temperature": 0.3,
            "maxOutputTokens": 100
        }
    }
    
    try:
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode('utf-8'),
            headers={
                'Content-Type': 'application/json',
                'x-goog-api-key': api_key
            },
            method='POST'
        )
        
        # 5 second timeout for responsiveness
        with urllib.request.urlopen(req, timeout=5) as response:
            res_data = json.loads(response.read().decode('utf-8'))
            
            # Extract response text
            candidates = res_data.get('candidates', [])
            if candidates:
                text = candidates[0].get('content', {}).get('parts', [])[0].get('text', '').strip()
                # Clean up any quotes or linebreaks in the model output
                text = text.replace('\n', ' ').replace('"', '').strip()
                if text:
                    return text
                    
            raise ValueError("Empty or malformed response structure from Gemini API.")
            
    except Exception as e:
        print(f"Gemini API request failed ({e}). Falling back to local explanation template.")
        # Fall back to template so the application never breaks
        return get_template_explanation(threat.attack_type, threat.source_ip, threat.destination_ip)
