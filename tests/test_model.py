import os
import pytest
import joblib
import torch
from src.predict import predict, get_model, MITRE_MAP
from src.train_deep_learning import CyberThreatCNN1D

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def test_random_forest_pipeline_loads():
    model = get_model()
    assert model is not None
    assert hasattr(model, "predict")
    assert hasattr(model, "predict_proba")
    assert len(model.classes_) == 6

def test_random_forest_inference():
    sample_flow = {
        'flow_duration': 8000,
        'tot_fwd_pkts': 1500,
        'tot_bwd_pkts': 5,
        'totlen_fwd_pkts': 95000,
        'totlen_bwd_pkts': 120,
        'fwd_pkt_len_mean': 63.3,
        'bwd_pkt_len_mean': 24.0,
        'flow_byts_s': 11890.0,
        'flow_pkts_s': 188.1,
        'flow_iat_mean': 2.1,
        'flow_iat_std': 0.8,
        'fwd_iat_mean': 2.0,
        'bwd_iat_mean': 0.5,
        'syn_flag_cnt': 1,
        'rst_flag_cnt': 0,
        'psh_flag_cnt': 0,
        'ack_flag_cnt': 0,
        'urg_flag_cnt': 0,
        'fwd_header_len': 30000,
        'bwd_header_len': 100,
        'down_up_ratio': 0.0,
        'pkt_len_variance': 45.2,
        'subflow_fwd_pkts': 1500
    }
    
    result = predict(sample_flow)
    assert 'attack_type' in result
    assert 'confidence' in result
    assert 'severity' in result
    assert 'mitre_id' in result
    assert 0.0 <= result['confidence'] <= 1.0
    assert result['severity'] in ['critical', 'high', 'medium', 'low']

def test_pytorch_cnn_forward_pass():
    # Instantiate PyTorch 1D-CNN
    cnn = CyberThreatCNN1D(in_features=23, num_classes=6)
    cnn.eval()

    # Dummy tensor with batch_size=4, channels=1, sequence_length=23
    dummy_input = torch.randn(4, 1, 23)
    with torch.no_grad():
        output = cnn(dummy_input)

    assert output.shape == (4, 6)
    # Check that outputs are finite logits
    assert not torch.isnan(output).any()
    assert not torch.isinf(output).any()
