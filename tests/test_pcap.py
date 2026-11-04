import os
import pytest
from src.pcap_analyzer import create_sample_pcap, parse_pcap, inspect_and_classify_flows

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMP_PCAP = os.path.join(PROJECT_ROOT, 'data', 'test_sample.pcap')

def test_pcap_generation_and_parsing():
    try:
        # 1. Generate test binary pcap
        create_sample_pcap(TEMP_PCAP)
        assert os.path.exists(TEMP_PCAP)
        assert os.path.getsize(TEMP_PCAP) > 100

        # 2. Parse raw packets into flows
        flows = parse_pcap(TEMP_PCAP)
        assert isinstance(flows, list)
        assert len(flows) > 0

        first_flow = flows[0]
        assert 'source_ip' in first_flow
        assert 'destination_ip' in first_flow
        assert 'port' in first_flow
        assert 'protocol' in first_flow
        assert 'fwd_pkts' in first_flow

        # 3. Classify flows without committing to DB
        results = inspect_and_classify_flows(flows, commit_to_db=False)
        assert len(results) == len(flows)
        for res in results:
            assert 'attack_type' in res
            assert 'confidence' in res
            assert 'severity' in res
            assert 'mitre_id' in res

    finally:
        if os.path.exists(TEMP_PCAP):
            os.remove(TEMP_PCAP)
