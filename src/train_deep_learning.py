import os
import sys
import time
import json
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, confusion_matrix
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_PATH = os.path.join(PROJECT_ROOT, 'data', 'threats_cleaned.csv')
MODEL_DIR = os.path.join(PROJECT_ROOT, 'ml')
PYTORCH_MODEL_PATH = os.path.join(MODEL_DIR, 'pytorch_model.pt')
DL_METRICS_PATH = os.path.join(MODEL_DIR, 'dl_metrics.json')
CURVE_PLOT_PATH = os.path.join(PROJECT_ROOT, 'data', 'dl_training_curves.png')

os.makedirs(MODEL_DIR, exist_ok=True)

FEATURE_COLUMNS = [
    'flow_duration', 'tot_fwd_pkts', 'tot_bwd_pkts', 'totlen_fwd_pkts', 'totlen_bwd_pkts',
    'fwd_pkt_len_mean', 'bwd_pkt_len_mean', 'flow_byts_s', 'flow_pkts_s',
    'flow_iat_mean', 'flow_iat_std', 'fwd_iat_mean', 'bwd_iat_mean',
    'syn_flag_cnt', 'rst_flag_cnt', 'psh_flag_cnt', 'ack_flag_cnt', 'urg_flag_cnt',
    'fwd_header_len', 'bwd_header_len', 'down_up_ratio', 'pkt_len_variance', 'subflow_fwd_pkts'
]

TARGET_COLUMN = 'attack_type'

class CyberFlowDataset(Dataset):
    def __init__(self, X, y):
        # Convert to float tensor and add channel dimension for 1D CNN: (N, 1, 23)
        self.X = torch.tensor(X, dtype=torch.float32).unsqueeze(1)
        self.y = torch.tensor(y, dtype=torch.long)

    def __len__(self):
        return len(self.y)

    def __getitem__(self, idx):
        return self.X[idx], self.y[idx]

class CyberThreatCNN1D(nn.Module):
    """
    Deep 1D-Convolutional Neural Network with Residual Bottleneck
    for raw network flow packet metric feature extraction and classification.
    """
    def __init__(self, in_features=23, num_classes=6):
        super(CyberThreatCNN1D, self).__init__()
        
        # Conv Block 1
        self.conv1 = nn.Conv1d(1, 32, kernel_size=3, padding=1)
        self.bn1 = nn.BatchNorm1d(32)
        self.act1 = nn.LeakyReLU(0.1)
        self.drop1 = nn.Dropout(0.2)
        
        # Conv Block 2
        self.conv2 = nn.Conv1d(32, 64, kernel_size=3, padding=1)
        self.bn2 = nn.BatchNorm1d(64)
        self.act2 = nn.LeakyReLU(0.1)
        self.pool1 = nn.MaxPool1d(kernel_size=2)
        
        # Flattened dimension after pool: 23 // 2 = 11 -> 64 * 11 = 704
        flat_dim = 64 * (in_features // 2)
        
        # Dense Head
        self.fc1 = nn.Linear(flat_dim, 128)
        self.bn_fc = nn.BatchNorm1d(128)
        self.act_fc = nn.LeakyReLU(0.1)
        self.drop2 = nn.Dropout(0.3)
        
        self.fc2 = nn.Linear(128, 64)
        self.act_fc2 = nn.LeakyReLU(0.1)
        
        self.classifier = nn.Linear(64, num_classes)

    def forward(self, x):
        x = self.drop1(self.act1(self.bn1(self.conv1(x))))
        x = self.pool1(self.act2(self.bn2(self.conv2(x))))
        x = x.view(x.size(0), -1)
        x = self.drop2(self.act_fc(self.bn_fc(self.fc1(x))))
        x = self.act_fc2(self.fc2(x))
        out = self.classifier(x)
        return out

def train_dl_model(epochs=15, batch_size=64, lr=0.001):
    print("=" * 70)
    print("  PHASE 2B: DEEP LEARNING MODEL (1D-CNN) TRAINING & BENCHMARK")
    print("=" * 70)

    if not os.path.exists(DATA_PATH):
        raise FileNotFoundError(f"Cleaned dataset not found at {DATA_PATH}.")

    print(f"Loading real CIC-IDS2017 dataset from {DATA_PATH}...")
    df = pd.read_csv(DATA_PATH)
    print(f"Dataset shape: {df.shape}")

    X_raw = df[FEATURE_COLUMNS].values
    unique_classes = sorted(df[TARGET_COLUMN].unique().tolist())
    class_to_idx = {c: i for i, c in enumerate(unique_classes)}
    idx_to_class = {i: c for i, c in enumerate(unique_classes)}
    y_raw = df[TARGET_COLUMN].map(class_to_idx).values

    # Stratified Train/Val/Test Split (70% train, 15% val, 15% test)
    X_train_full, X_test, y_train_full, y_test = train_test_split(
        X_raw, y_raw, test_size=0.15, random_state=42, stratify=y_raw
    )
    X_train, X_val, y_train, y_val = train_test_split(
        X_train_full, y_train_full, test_size=0.1765, random_state=42, stratify=y_train_full
    )

    # Standard Scaling
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_val_scaled = scaler.transform(X_val)
    X_test_scaled = scaler.transform(X_test)

    train_dataset = CyberFlowDataset(X_train_scaled, y_train)
    val_dataset = CyberFlowDataset(X_val_scaled, y_val)
    test_dataset = CyberFlowDataset(X_test_scaled, y_test)

    train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=batch_size, shuffle=False)
    test_loader = DataLoader(test_dataset, batch_size=batch_size, shuffle=False)

    print(f"Data Splits: Train={len(train_dataset)}, Validation={len(val_dataset)}, Test={len(test_dataset)}")
    print(f"Target Classes ({len(unique_classes)}): {unique_classes}")

    # Model, Loss, Optimizer
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    print(f"Compute Engine: {device}")

    model = CyberThreatCNN1D(in_features=len(FEATURE_COLUMNS), num_classes=len(unique_classes)).to(device)
    criterion = nn.CrossEntropyLoss()
    optimizer = torch.optim.AdamW(model.parameters(), lr=lr, weight_decay=1e-4)
    scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(optimizer, mode='min', factor=0.5, patience=2)

    history = {
        'epoch': [],
        'train_loss': [],
        'val_loss': [],
        'train_acc': [],
        'val_acc': []
    }

    print("\n--- Commencing PyTorch 1D-CNN Epoch Training ---")
    print(f"{'Epoch':<8} | {'Train Loss':<12} | {'Val Loss':<12} | {'Train Acc':<12} | {'Val Acc':<12} | {'Time':<8}")
    print("-" * 75)

    start_training_time = time.time()
    best_val_loss = float('inf')

    for epoch in range(1, epochs + 1):
        t_epoch_start = time.time()
        
        # Training Phase
        model.train()
        train_loss = 0.0
        train_correct = 0
        total_train = 0

        for batch_X, batch_y in train_loader:
            batch_X, batch_y = batch_X.to(device), batch_y.to(device)
            optimizer.zero_grad()
            outputs = model(batch_X)
            loss = criterion(outputs, batch_y)
            loss.backward()
            optimizer.step()

            train_loss += loss.item() * batch_X.size(0)
            preds = outputs.argmax(dim=1)
            train_correct += (preds == batch_y).sum().item()
            total_train += batch_y.size(0)

        epoch_train_loss = train_loss / total_train
        epoch_train_acc = (train_correct / total_train) * 100

        # Validation Phase
        model.eval()
        val_loss = 0.0
        val_correct = 0
        total_val = 0

        with torch.no_grad():
            for batch_X, batch_y in val_loader:
                batch_X, batch_y = batch_X.to(device), batch_y.to(device)
                outputs = model(batch_X)
                loss = criterion(outputs, batch_y)

                val_loss += loss.item() * batch_X.size(0)
                preds = outputs.argmax(dim=1)
                val_correct += (preds == batch_y).sum().item()
                total_val += batch_y.size(0)

        epoch_val_loss = val_loss / total_val
        epoch_val_acc = (val_correct / total_val) * 100
        scheduler.step(epoch_val_loss)

        epoch_time = time.time() - t_epoch_start

        history['epoch'].append(epoch)
        history['train_loss'].append(round(epoch_train_loss, 4))
        history['val_loss'].append(round(epoch_val_loss, 4))
        history['train_acc'].append(round(epoch_train_acc, 2))
        history['val_acc'].append(round(epoch_val_acc, 2))

        print(f"Epoch {epoch:<2}/{epochs:<2} | {epoch_train_loss:<12.4f} | {epoch_val_loss:<12.4f} | {epoch_train_acc:<11.2f}% | {epoch_val_acc:<11.2f}% | {epoch_time:5.2f}s")

    total_training_time = time.time() - start_training_time
    print("-" * 75)
    print(f"PyTorch training completed in {total_training_time:.2f} seconds.")

    # Final Evaluation on Unseen Test Split
    print("\nEvaluating on Held-Out Test Split (15%)...")
    model.eval()
    test_preds = []
    test_targets = []
    
    t_inf_start = time.perf_counter()
    with torch.no_grad():
        for batch_X, batch_y in test_loader:
            batch_X = batch_X.to(device)
            outputs = model(batch_X)
            preds = outputs.argmax(dim=1).cpu().numpy()
            test_preds.extend(preds)
            test_targets.extend(batch_y.numpy())
    t_inf_total = time.perf_counter() - t_inf_start
    test_latency_us = round((t_inf_total / len(test_targets)) * 1e6, 2)

    test_acc = accuracy_score(test_targets, test_preds)
    test_prec, test_rec, test_f1, _ = precision_recall_fscore_support(test_targets, test_preds, average='macro', zero_division=0)

    print(f"Deep Learning (1D-CNN) Test Accuracy: {test_acc * 100:.2f}%")
    print(f"Deep Learning (1D-CNN) Macro F1:      {test_f1 * 100:.2f}%")
    print(f"Deep Learning (1D-CNN) Inference Latency: {test_latency_us} us / flow")

    # Save PyTorch Model
    print(f"\nSaving PyTorch weights to {PYTORCH_MODEL_PATH}...")
    torch.save({
        'model_state_dict': model.state_dict(),
        'scaler_mean': scaler.mean_.tolist(),
        'scaler_scale': scaler.scale_.tolist(),
        'classes': unique_classes,
        'feature_columns': FEATURE_COLUMNS
    }, PYTORCH_MODEL_PATH)

    # Class-wise metrics
    p_class, r_class, f1_class, s_class = precision_recall_fscore_support(
        test_targets, test_preds, labels=list(range(len(unique_classes))), zero_division=0
    )
    class_metrics = []
    for idx, label in enumerate(unique_classes):
        class_metrics.append({
            "class": label,
            "precision": f"{p_class[idx] * 100:.2f}%",
            "recall": f"{r_class[idx] * 100:.2f}%",
            "f1": f"{f1_class[idx] * 100:.2f}%",
            "support": str(int(s_class[idx]))
        })

    # Save Metrics & Training History JSON
    metrics_payload = {
        "model_name": "1D-Convolutional Neural Network (PyTorch)",
        "architecture": "Conv1D(32) -> Conv1D(64) -> MaxPool1D -> Dense(128) -> Dense(64) -> Softmax",
        "test_accuracy": round(float(test_acc * 100), 2),
        "test_macro_f1": round(float(test_f1 * 100), 2),
        "test_precision": round(float(test_prec * 100), 2),
        "test_recall": round(float(test_rec * 100), 2),
        "inference_latency_us": test_latency_us,
        "total_epochs": epochs,
        "batch_size": batch_size,
        "history": history,
        "class_metrics": class_metrics
    }

    with open(DL_METRICS_PATH, 'w') as f:
        json.dump(metrics_payload, f, indent=2)
    print(f"Saved DL metrics & history to {DL_METRICS_PATH}")

    # Generate Learning Curves Plot
    plt.figure(figsize=(12, 5))
    
    # Loss Curve
    plt.subplot(1, 2, 1)
    plt.plot(history['epoch'], history['train_loss'], 'b-o', label='Train Loss')
    plt.plot(history['epoch'], history['val_loss'], 'r-s', label='Val Loss')
    plt.title('1D-CNN Cross-Entropy Loss vs Epochs')
    plt.xlabel('Epoch')
    plt.ylabel('Loss')
    plt.grid(True, linestyle='--', alpha=0.6)
    plt.legend()

    # Accuracy Curve
    plt.subplot(1, 2, 2)
    plt.plot(history['epoch'], history['train_acc'], 'b-o', label='Train Accuracy')
    plt.plot(history['epoch'], history['val_acc'], 'g-s', label='Val Accuracy')
    plt.title('1D-CNN Multi-Class Accuracy vs Epochs')
    plt.xlabel('Epoch')
    plt.ylabel('Accuracy (%)')
    plt.grid(True, linestyle='--', alpha=0.6)
    plt.legend()

    plt.tight_layout()
    plt.savefig(CURVE_PLOT_PATH, dpi=150)
    plt.close()
    print(f"Exported training curves graph to {CURVE_PLOT_PATH}")

    # Also update ml/metrics.json so the Models dashboard includes the Deep Learning architecture
    METRICS_JSON = os.path.join(MODEL_DIR, 'metrics.json')
    if os.path.exists(METRICS_JSON):
        with open(METRICS_JSON, 'r') as f:
            base_metrics = json.load(f)
        
        # Add 1D-CNN to benchmark_comparison if not already present
        comps = base_metrics.get('benchmark_comparison', [])
        cnn_entry = {
            "name": "1D-CNN (PyTorch)",
            "type": "Deep Convolutional Neural Network",
            "accuracy": round(float(test_acc * 100), 2),
            "macro_f1": round(float(test_f1 * 100), 2),
            "precision": round(float(test_prec * 100), 2),
            "recall": round(float(test_rec * 100), 2),
            "latency_us": test_latency_us,
            "train_time_s": round(total_training_time, 2),
            "selected": False
        }
        # Replace or append
        existing_idx = next((i for i, c in enumerate(comps) if c['name'] == cnn_entry['name']), None)
        if existing_idx is not None:
            comps[existing_idx] = cnn_entry
        else:
            comps.append(cnn_entry)
        
        base_metrics['benchmark_comparison'] = comps
        base_metrics['deep_learning'] = metrics_payload
        
        with open(METRICS_JSON, 'w') as f:
            json.dump(base_metrics, f, indent=2)
        print(f"Updated global metrics.json with PyTorch 1D-CNN benchmarks!")

    print("\n--- Deep Learning (1D-CNN) Pipeline Completed Successfully ---")

if __name__ == '__main__':
    train_dl_model()
