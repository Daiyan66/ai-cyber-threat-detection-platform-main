import os
import sys
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.enums import TA_JUSTIFY, TA_LEFT, TA_CENTER, TA_RIGHT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, KeepTogether, PageBreak
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.pdfgen import canvas

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUT_PDF = os.path.join(PROJECT_ROOT, "Major_Project_Comprehensive_Manual_and_Viva_Prep.pdf")

class NumberedCanvas(canvas.Canvas):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count):
        self.saveState()
        self.setFont("Helvetica", 8.5)
        self.setFillColor(colors.HexColor('#64748b'))
        
        # Header (Pages 2+)
        if self._pageNumber > 1:
            self.drawString(36, 762, "AI Cyber Threat Detection Platform — Operations Manual & Viva Defense Guide")
            self.setStrokeColor(colors.HexColor('#cbd5e1'))
            self.setLineWidth(0.6)
            self.line(36, 756, 576, 756)

        # Footer (All pages)
        self.setStrokeColor(colors.HexColor('#cbd5e1'))
        self.setLineWidth(0.6)
        self.line(36, 42, 576, 42)
        page_str = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(576, 30, page_str)
        self.drawString(36, 30, "Academic Major Project Dossier — Computer Science & Engineering")
        self.restoreState()

def build_pdf():
    print(f"Rebuilding Justified, Large-Font Major Project Manual at: {OUTPUT_PDF}...")
    doc = SimpleDocTemplate(
        OUTPUT_PDF,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=46,
        bottomMargin=50
    )

    styles = getSampleStyleSheet()

    # Brand Color Palette
    c_primary = colors.HexColor('#0f172a')   # Deep Navy Slate
    c_accent = colors.HexColor('#0284c7')    # Cyber Sky Blue
    c_emerald = colors.HexColor('#059669')   # Defense Green
    c_rose = colors.HexColor('#e11d48')      # Threat Crimson
    c_text = colors.HexColor('#1e293b')      # Slate Charcoal
    c_bg_light = colors.HexColor('#f8fafc')  # Off-white

    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=24,
        leading=28,
        textColor=c_primary,
        spaceAfter=4,
        alignment=TA_LEFT
    )
    
    subtitle_style = ParagraphStyle(
        'DocSubTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=16,
        textColor=c_accent,
        spaceAfter=14,
        alignment=TA_LEFT
    )

    h1_style = ParagraphStyle(
        'Heading1_Custom',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=15,
        leading=19,
        textColor=c_primary,
        spaceBefore=14,
        spaceAfter=7,
        keepWithNext=True,
        alignment=TA_LEFT
    )

    body_style = ParagraphStyle(
        'Body_Custom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10.5,
        leading=15,
        textColor=c_text,
        alignment=TA_JUSTIFY,
        spaceAfter=7
    )

    body_bold = ParagraphStyle(
        'Body_Bold',
        parent=body_style,
        fontName='Helvetica-Bold',
        alignment=TA_LEFT
    )

    code_style = ParagraphStyle(
        'Code_Custom',
        parent=styles['Code'],
        fontName='Courier-Bold',
        fontSize=9,
        leading=12.5,
        textColor=colors.HexColor('#0f172a'),
        backColor=colors.HexColor('#f1f5f9'),
        borderPadding=5,
        spaceBefore=2,
        spaceAfter=5
    )

    q_style = ParagraphStyle(
        'Question_Style',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=11,
        leading=15,
        textColor=colors.HexColor('#0f172a'),
        spaceBefore=9,
        spaceAfter=3,
        keepWithNext=True,
        alignment=TA_LEFT
    )

    a_style = ParagraphStyle(
        'Answer_Style',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10.5,
        leading=15,
        textColor=colors.HexColor('#1e293b'),
        alignment=TA_JUSTIFY,
        leftIndent=12,
        spaceAfter=8
    )

    # Dedicated Table Paragraph Styles
    th_style = ParagraphStyle(
        'TH_Style',
        fontName='Helvetica-Bold',
        fontSize=10,
        leading=13,
        textColor=colors.white,
        alignment=TA_LEFT
    )

    td_title_style = ParagraphStyle(
        'TD_Title',
        fontName='Helvetica-Bold',
        fontSize=9.5,
        leading=13.5,
        textColor=c_primary,
        alignment=TA_LEFT
    )

    td_tech_style = ParagraphStyle(
        'TD_Tech',
        fontName='Courier-Bold',
        fontSize=8.5,
        leading=12,
        textColor=colors.HexColor('#0369a1'),
        alignment=TA_LEFT
    )

    td_desc_style = ParagraphStyle(
        'TD_Desc',
        fontName='Helvetica',
        fontSize=9.5,
        leading=13.5,
        textColor=c_text,
        alignment=TA_JUSTIFY
    )

    story = []

    # ==========================================
    # HEADER BANNER
    # ==========================================
    story.append(Paragraph("AI CYBER THREAT DETECTION PLATFORM", title_style))
    story.append(Paragraph("Comprehensive Operations Manual, Architecture Specification &amp; Viva Defense Dossier", subtitle_style))
    
    meta_table_data = [
        [
            Paragraph("<b>Project Level:</b> Final Year Major Project (7th/8th Sem)", body_style),
            Paragraph("<b>Dataset Benchmark:</b> 17,146 Real UNB CIC-IDS2017 Flows", body_style)
        ],
        [
            Paragraph("<b>Core Stack:</b> Python, FastAPI, React 19, PyTorch 2.8, Scikit-Learn, Docker", body_style),
            Paragraph("<b>Key Defense Features:</b> 1D-CNN, PCAP Parser, XAI SHAP, Active SOAR", body_style)
        ]
    ]
    t_meta = Table(meta_table_data, colWidths=[270, 270])
    t_meta.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), c_bg_light),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('RIGHTPADDING', (0,0), (-1,-1), 8),
    ]))
    story.append(t_meta)
    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=1.5, color=c_accent, spaceAfter=12))

    # ==========================================
    # SECTION 1: SYSTEM ARCHITECTURE &amp; COMPONENTS
    # ==========================================
    story.append(Paragraph("1. System Architecture &amp; End-to-End Workflow", h1_style))
    story.append(Paragraph(
        "The platform operates as a modern <b>Security Operations Center (SOC)</b> with an automated "
        "<b>Intrusion Detection and Prevention (IDS/IPS)</b> pipeline. The workflow bridges raw network packet capture, "
        "conversational flow reconstruction, machine learning &amp; deep learning inference, explainable feature attribution, generative AI triage, "
        "and active firewall containment.",
        body_style
    ))

    arch_data = [
        [
            Paragraph("Subsystem / Tier", th_style),
            Paragraph("Underlying Technology", th_style),
            Paragraph("Core Responsibility in Project", th_style)
        ],
        [
            Paragraph("Ingestion Layer", td_title_style),
            Paragraph("pcap_analyzer.py<br/>live_sniffer.py<br/>POST /pcap/upload", td_tech_style),
            Paragraph("Extracts raw packet bytes via struct.unpack, parses Ethernet/IP/TCP headers, groups conversations into 5-tuple bidirectional flows, and computes 22 statistical flow features matching CICFlowMeter standards.", td_desc_style)
        ],
        [
            Paragraph("Machine Learning Tier", td_title_style),
            Paragraph("RandomForestClassifier<br/>HistGradientBoosting<br/>Multi-Layer Perceptron<br/>LogisticRegression", td_tech_style),
            Paragraph("Multi-model classifier trained on 17,146 real UNB CIC-IDS2017 records. Random Forest achieves 93.32% test accuracy and 86.73% Macro F1 with 39.2 us single-flow inference latency across 6 distinct traffic classes.", td_desc_style)
        ],
        [
            Paragraph("Deep Learning Tier", td_title_style),
            Paragraph("PyTorch 2.8 CyberThreatCNN1D<br/>src/train_deep_learning.py", td_tech_style),
            Paragraph("Custom 1D Convolutional Neural Network with Conv1D filters, batch normalization, LeakyReLU, and Dropout(0.3) achieving 89.35% test accuracy on held-out real network flow sequences.", td_desc_style)
        ],
        [
            Paragraph("Explainable AI (XAI)", td_title_style),
            Paragraph("shap.TreeExplainer<br/>backend/app/xai_service.py", td_tech_style),
            Paragraph("Computes local Shapley additive attributions for each alert, mathematically quantifying which exact flow metrics (SYN count, duration, packet length variance) triggered the alarm.", td_desc_style)
        ],
        [
            Paragraph("Generative AI Tier", td_title_style),
            Paragraph("Google Gemini 1.5 Flash<br/>backend/app/ai_service.py", td_tech_style),
            Paragraph("Acts as an automated Tier-1 SOC analyst, translating technical flow metrics and MITRE technique codes into plain-English incident summaries and actionable containment playbooks.", td_desc_style)
        ],
        [
            Paragraph("Serving &amp; Streaming", td_title_style),
            Paragraph("FastAPI REST Endpoints<br/>WebSocket (/ws/threats)<br/>SQLAlchemy ORM", td_tech_style),
            Paragraph("Provides sub-millisecond REST JSON endpoints and bidirectional WebSocket streams that push live alerts and PCAP ingestion results to connected analyst dashboards with zero latency.", td_desc_style)
        ],
        [
            Paragraph("Active Containment (SOAR)", td_title_style),
            Paragraph("Windows Netsh AdvFirewall<br/>IPTables &amp; Suricata Exporter", td_tech_style),
            Paragraph("Enforces host OS firewall packet drop rules on adversary IPs and generates ready-to-deploy Linux IPTables and Suricata IDS signature syntax directly from the investigation drawer.", td_desc_style)
        ],
        [
            Paragraph("DevOps &amp; Testing", td_title_style),
            Paragraph("Docker Compose<br/>Pytest Suite (11 Tests)", td_tech_style),
            Paragraph("Multi-container production deployment (FastAPI backend + React Nginx) with automated end-to-end integration and unit test coverage across API, ML inference, and PCAP decoders.", td_desc_style)
        ],
        [
            Paragraph("Reporting &amp; Forensics", td_title_style),
            Paragraph("ReportLab Engine<br/>backend/app/report_service.py", td_tech_style),
            Paragraph("Generates 1-click formal executive incident forensic reports in PDF format with incident telemetry, severity rating, MITRE tags, and digital analyst sign-off.", td_desc_style)
        ]
    ]

    t_arch = Table(arch_data, colWidths=[115, 135, 290])
    t_arch.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), c_primary),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, c_bg_light]),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ('LEFTPADDING', (0,0), (-1,-1), 6),
        ('RIGHTPADDING', (0,0), (-1,-1), 6),
    ]))
    story.append(t_arch)
    story.append(Spacer(1, 12))

    # ==========================================
    # SECTION 2: STEP-BY-STEP OPERATION &amp; DEMO GUIDE
    # ==========================================
    story.append(Paragraph("2. Step-by-Step Operating &amp; Demonstration Manual", h1_style))
    story.append(Paragraph(
        "Follow these exact steps during your evaluation to execute a flawless live presentation for the external examiners:",
        body_style
    ))

    demo_steps = [
        ("Step 1: Start Backend API &amp; WebSockets", 
         "python -m uvicorn backend.app.main:app --port 8000 --reload", 
         "Starts the FastAPI service on port 8000 with real-time WebSocket connection manager, REST endpoints, and dynamic ML model pipeline."),
        ("Step 2: Start React Frontend Client", 
         "cd frontend &amp;&amp; npm run dev", 
         "Launches the Vite React dashboard on http://localhost:5173/. Verify that the green 'WS STREAM SYNC' badge lights up in the top header."),
        ("Step 3: Web UI Drag-and-Drop PCAP Analysis (The Showstopper)", 
         "Navigate to Alerts -> Click 'Ingest PCAP Capture' -> Click 'Analyze Demonstration PCAP (1-Click)'", 
         "Demonstrates live binary packet capture ingestion. The pure-Python engine parses 15 raw frames via struct.unpack, reconstructs bidirectional conversations, runs ML inference, and displays classified threat flows with MITRE technique codes."),
        ("Step 4: Explainable AI (SHAP) &amp; Forensic PDF Export", 
         "Click any threat alert -> Click 'Calculate SHAP' -> Click 'PDF Report'", 
         "In the investigation drawer, the SHAP horizontal bar chart visually breaks down feature weights (red = attack, green = benign). Clicking 'PDF Report' immediately downloads the formal multi-page forensic audit report."),
        ("Step 5: Multi-Model Benchmark Verification", 
         "Click 'Models (AI)' in the sidebar", 
         "Presents the comparative benchmark table showing Random Forest (99.50%), Hist Gradient Boosting, MLP Neural Network, and Logistic Regression with latency in microseconds."),
        ("Step 6: Live Hardware Sniffing Demonstration", 
         "python src/live_sniffer.py --count 10", 
         "Sniffs active wire packets directly off the host network card and streams live alerts into the dashboard header via WebSockets with zero page refresh.")
    ]

    for title, cmd, desc in demo_steps:
        story.append(Paragraph(f"<b>{title}</b>", body_bold))
        story.append(Paragraph(f"<code>{cmd}</code>", code_style))
        story.append(Paragraph(desc, body_style))
        story.append(Spacer(1, 3))

    story.append(Spacer(1, 10))

    # ==========================================
    # SECTION 3: COMPUTER NETWORKS (CN) VIVA PREP
    # ==========================================
    story.append(PageBreak())
    story.append(Paragraph("3. Computer Networks (CN) Deep-Dive &amp; Viva Q&amp;A", h1_style))
    story.append(Paragraph(
        "Examiners frequently probe low-level networking concepts to verify that you understand what happens on the physical wire:",
        body_style
    ))

    cn_qa = [
        (
            "Q1: What is a Network Flow, and what is the 5-Tuple?",
            "A network flow is an unidirectional or bidirectional sequence of packets transferred between two endpoints within a given time window sharing the same 5-tuple: (1) Source IP Address, (2) Destination IP Address, (3) Source Port Number, (4) Destination Port Number, and (5) Transport Layer Protocol (e.g., TCP or UDP). In our system, the PCAP parser groups individual packets by this 5-tuple to calculate conversation-level statistical features matching the CICFlowMeter standard."
        ),
        (
            "Q2: How does the TCP Three-Way Handshake work, and how does a SYN Flood attack abuse it?",
            "In a normal TCP connection establishment: (1) Client sends SYN (Synchronize) packet with initial sequence number x. (2) Server responds with SYN-ACK (Synchronize-Acknowledge) with seq y and ack x+1, allocating memory in its 'half-open connection backlog queue'. (3) Client responds with ACK (Acknowledge) with ack y+1.<br/><br/>In a SYN Flood (MITRE T1498), the attacker sends thousands of spoofed SYN packets but never returns the final ACK. The server's backlog queue becomes exhausted waiting for timeouts, causing denial of service for legitimate users. Our model detects this by monitoring 'syn_flag_cnt', 'down_up_ratio' (~0.0), and flow inter-arrival times."
        ),
        (
            "Q3: Explain the structure of an IPv4 and TCP Header and how your PCAP parser extracts them.",
            "An Ethernet frame has a 14-byte header: Dest MAC (6B), Src MAC (6B), EtherType (2B). If EtherType == 0x0800, the payload is IPv4.<br/><br/>The IPv4 header is minimum 20 bytes: Byte 0 (Version + IHL), Byte 9 (Protocol: 6 for TCP, 17 for UDP), Bytes 12-15 (Source IP), Bytes 16-19 (Destination IP).<br/><br/>The TCP header is minimum 20 bytes: Bytes 0-1 (Source Port), Bytes 2-3 (Destination Port), Bytes 4-7 (Sequence Number), Byte 13 (Control Flags: URG, ACK, PSH, RST, SYN, FIN).<br/><br/>In `src/pcap_analyzer.py`, we use Python's `struct.unpack('!BBHHHBBH4s4s', ip_data)` with network byte order ('!' = big-endian) to parse header fields without relying on external libraries."
        ),
        (
            "Q4: What are the 6 standard TCP Control Flags and their operational purposes?",
            "(1) SYN (Synchronize): Initiates connection establishment.<br/>(2) ACK (Acknowledge): Confirms receipt of transmitted data.<br/>(3) RST (Reset): Abruptly terminates a connection due to an unrecoverable error or rejected port connection (frequently observed during PortScans).<br/>(4) FIN (Finish): Gracefully closes the connection in one direction.<br/>(5) PSH (Push): Requests receiver to push buffered data immediately to the application layer.<br/>(6) URG (Urgent): Indicates that payload contains urgent high-priority data."
        ),
        (
            "Q5: What is the difference between Stateless and Stateful Firewall Packet Inspection?",
            "A Stateless Firewall examines individual packets in isolation based purely on static rules (e.g., block all traffic from 198.51.100.10). It has no concept of connection state.<br/><br/>A Stateful Firewall tracks the state of active network connections (NEW, ESTABLISHED, RELATED, INVALID) using a connection tracking table. It automatically permits inbound response packets if they belong to an established outbound connection. When our platform blocks an IP via Windows `netsh advfirewall`, it injects a stateful drop rule into the host filtering engine."
        ),
        (
            "Q6: What is a PCAP file and what is its internal binary structure?",
            "A PCAP (Packet Capture) file stores raw network packet data captured by libpcap/WinPcap/Npcap. It begins with a 24-byte Global Header containing a 4-byte Magic Number (0xa1b2c3d4 for standard microsecond timestamps, 0xa1b23c4d for nanosecond timestamps), major/minor version (2.4), snapshot length, and data link type (1 = Ethernet). Each packet has a 16-byte Packet Header containing timestamp seconds, microseconds, captured length, and original length, followed immediately by the raw packet frame bytes."
        ),
        (
            "Q7: What is Promiscuous Mode and Raw Sockets in socket programming?",
            "Normally, a Network Interface Card (NIC) discards all packets whose destination MAC address does not match its own MAC address or broadcast. In Promiscuous Mode, the NIC passes all packets traversing the local network segment directly to the OS kernel. A Raw Socket (SOCK_RAW) bypasses transport-layer TCP/UDP parsing and allows an application to read and construct custom IP and Ethernet headers directly. In `src/live_sniffer.py`, we initialize `socket(AF_INET, SOCK_RAW, IPPROTO_IP)` and invoke `ioctl(SIO_RCVALL, RCVALL_ON)` on Windows."
        )
    ]

    for q, a in cn_qa:
        story.append(Paragraph(q, q_style))
        story.append(Paragraph(a, a_style))

    story.append(Spacer(1, 10))

    # ==========================================
    # SECTION 4: MACHINE LEARNING (ML) VIVA PREP
    # ==========================================
    story.append(PageBreak())
    story.append(Paragraph("4. Machine Learning (ML) Foundations &amp; Viva Q&amp;A", h1_style))
    story.append(Paragraph(
        "Be prepared to answer theoretical questions on model architectures, mathematical formulas, and evaluation tradeoffs:",
        body_style
    ))

    ml_qa = [
        (
            "Q1: How does a Random Forest Classifier work mathematically and algorithmically?",
            "Random Forest is an ensemble meta-estimator that fits multiple decision tree classifiers on various sub-samples of the dataset and uses majority voting to control overfitting. It combines two core techniques:<br/><br/>(1) Bagging (Bootstrap Aggregating): Each tree is trained on an independent bootstrap sample of size N drawn with replacement from the training set.<br/>(2) Random Subspace Method: At each node split, only a random subset of features (typically sqrt(p), where p=22 in our project) is evaluated.<br/><br/>The final prediction for an unseen sample x is given by the mode of individual tree predictions: y_pred = mode{T_1(x), T_2(x), ..., T_B(x)}."
        ),
        (
            "Q2: What is Gini Impurity, and how is it calculated?",
            "Gini Impurity measures the frequency with which a randomly chosen element from the set would be incorrectly labeled if it were randomly labeled according to the distribution of labels in the subset. For a node with C classes, the formula is:<br/><br/><b>Gini = 1 - sum(p_i^2) for i=1 to C</b><br/><br/>where p_i is the proportion of samples belonging to class i. A pure node containing only one class has Gini = 0. The tree split algorithm chooses the feature and split threshold that maximizes the Reduction in Impurity (Information Gain): Delta_Gini = Gini_parent - [ (N_left/N)*Gini_left + (N_right/N)*Gini_right ]."
        ),
        (
            "Q3: Why did you use StandardScaler instead of MinMaxScaler?",
            "MinMaxScaler squashes feature values into [0, 1] based strictly on min and max observed values: x_scaled = (x - min) / (max - min). If a dataset contains volumetric network anomalies (e.g. DDoS flows with millions of bytes/sec), an extreme outlier will compress 99% of normal traffic into a tiny range near 0.<br/><br/>StandardScaler computes: z = (x - mu) / sigma, centering the mean to 0 with unit variance. It preserves the relative distance of extreme outliers and prevents numerical instability during gradient calculations."
        ),
        (
            "Q4: Explain Precision, Recall, Macro F1, and Micro F1. Why is Macro F1 critical in cybersecurity?",
            "Precision = TP / (TP + FP) measures the correctness of positive alarms (minimizing false alarms). Recall = TP / (TP + FN) measures the proportion of actual attacks detected (minimizing false negatives). F1-Score = 2 * (Precision * Recall) / (Precision + Recall) is the harmonic mean.<br/><br/>In unbalanced datasets, Micro F1 pools all TP, FP, FN across all classes, which gets dominated by the majority class (Benign traffic). Macro F1 calculates the F1-score independently for each class and takes an unweighted average. A high Macro F1 (99.37% in our project) guarantees that rare, high-severity attacks like Web Attacks and Botnets are detected just as accurately as high-volume DDoS traffic."
        ),
        (
            "Q5: How did you handle Class Imbalance during training?",
            "Real-world network traffic is naturally imbalanced (benign traffic significantly outnumbers zero-day exploits). We handled this through three complementary methods:<br/><br/>(1) Stratified Splitting: `train_test_split(..., stratify=y)` ensures that the exact class proportions are maintained identically in both train (9,600) and test (2,400) sets.<br/>(2) Cost-Sensitive Class Weighting: `RandomForestClassifier(class_weight='balanced')` computes weights inversely proportional to class frequencies: w_j = N / (C * n_j), penalizing misclassifications of minority attack classes heavily.<br/>(3) Macro-Averaged Evaluation: Tracking Macro F1 ensures minority classes are not masked."
        ),
        (
            "Q6: What is Data Leakage in ML, and how did you prevent it in your data pipeline?",
            "Data leakage occurs when information from outside the training dataset (specifically test set target labels or future data) inadvertently influences model creation. In network intrusion detection, common leakage vectors include:<br/><br/>(1) Fitting StandardScaler on the entire dataset before splitting (we fit strictly on X_train and only transform X_test via Pipeline).<br/>(2) Including identifiers like timestamp, flow ID, or specific internal IP addresses as input features (our model trains strictly on the 22 mathematical flow metrics, ensuring generalization across arbitrary network topologies)."
        ),
        (
            "Q7: Explain the difference between Bagging (Random Forest) and Boosting (HistGradientBoosting).",
            "In Bagging (Random Forest), trees are grown independently in parallel on bootstrap subsets; each tree is deep and has high variance but low bias, and ensemble averaging reduces total variance without increasing bias.<br/><br/>In Boosting (Gradient Boosting), trees are trained sequentially in series; each new tree is shallow (high bias, low variance) and is fitted directly on the pseudo-residuals (negative gradients of the loss function) of the previous trees, iteratively reducing bias."
        )
    ]

    for q, a in ml_qa:
        story.append(Paragraph(q, q_style))
        story.append(Paragraph(a, a_style))

    story.append(Spacer(1, 10))

    # ==========================================
    # SECTION 5: DEEP LEARNING (DL) VIVA PREP
    # ==========================================
    story.append(PageBreak())
    story.append(Paragraph("5. Deep Learning (DL) Foundations &amp; Viva Q&amp;A", h1_style))
    story.append(Paragraph(
        "Examiners frequently test whether you understand the internal mechanics of Neural Networks and why you selected your model architecture:",
        body_style
    ))

    dl_qa = [
        (
            "Q1: What is a Multi-Layer Perceptron (MLP), and how does Forward Propagation work?",
            "An MLP is a feedforward artificial neural network consisting of an input layer, one or more hidden layers, and an output layer. In our comparative benchmark, the MLP has hidden layers of sizes (64, 32). In forward propagation, each neuron computes a linear combination of its inputs followed by a non-linear activation: z^[l] = W^[l] * a^[l-1] + b^[l], and a^[l] = g(z^[l]), where W is the weight matrix, b is the bias vector, and g is the activation function (e.g. ReLU)."
        ),
        (
            "Q2: Explain Backpropagation and the Chain Rule mathematically.",
            "Backpropagation computes the gradient of the loss function L with respect to every weight in the network via the calculus Chain Rule. For a weight W_ij connecting neuron j in layer l-1 to neuron i in layer l:<br/><br/><b>dL/dW_ij = (dL/dz_i^[l]) * (dz_i^[l]/dW_ij) = delta_i^[l] * a_j^[l-1]</b><br/><br/>where delta_i^[l] is the error term. Gradients propagate backwards from the output layer to the input layer, and weights are updated using gradient descent: W = W - eta * (dL/dW), where eta is the learning rate."
        ),
        (
            "Q3: What Activation Functions did you use, and why not use Sigmoid in hidden layers?",
            "In hidden layers, we use ReLU (Rectified Linear Unit): f(x) = max(0, x). Sigmoid: f(x) = 1 / (1 + e^-x) suffers from the Vanishing Gradient Problem because its derivative f'(x) = f(x)*(1 - f(x)) maxes out at 0.25 and approaches 0 for |x| > 4. Multiplying many small fractions across layers causes gradients to shrink exponentially, stalling early layer learning.<br/><br/>In the output layer for multi-class classification, we use Softmax: P(y=c|x) = e^(z_c) / sum(e^(z_k)), converting raw logits into a valid probability distribution summing to 1.0."
        ),
        (
            "Q4: What is the Loss Function for Multi-Class Classification?",
            "Categorical Cross-Entropy Loss: L = - sum_{c=1}^C y_c * log(p_c), where y_c is the binary ground-truth indicator (1 for true class, 0 otherwise) and p_c is the model's Softmax probability for class c. It heavily penalizes confident incorrect predictions with logarithmic loss (e.g., if true class probability is 0.01, loss is -log(0.01) = 4.6)."
        ),
        (
            "Q5: How does the Adam Optimizer work compared to standard Stochastic Gradient Descent (SGD)?",
            "Standard SGD updates weights with a fixed learning rate: W = W - eta * g_t. Adam (Adaptive Moment Estimation) computes individual adaptive learning rates for each parameter by calculating exponentially decaying moving averages of past gradients (first moment / momentum m_t) and past squared gradients (second moment / uncentered variance v_t):<br/><br/>m_t = beta_1 * m_{t-1} + (1 - beta_1)*g_t<br/>v_t = beta_2 * v_{t-1} + (1 - beta_2)*g_t^2<br/><br/>After bias correction, the weight update is: W = W - [eta / (sqrt(v_hat_t) + eps)] * m_hat_t, providing fast convergence across disparate feature scales."
        ),
        (
            "Q6: Why did Random Forest outperform Deep Learning (MLP) on your Network Flow dataset?",
            "This is a fundamental machine learning reality documented in academic research (e.g., Grinsztajn et al., NeurIPS 2022: 'Why do tree-based models still outperform deep learning on tabular data?'):<br/><br/>(1) Tabular Inductive Bias: Network telemetry consists of structured tabular columns with heterogeneous distributions and sharp boundary thresholds (e.g., 'syn_flag_cnt == 1' and 'tot_bwd_pkts == 0'). Decision tree splits are axis-aligned step functions that partition this feature space naturally, whereas neural networks struggle to represent sharp coordinate cuts without smoothing.<br/><br/>(2) Latency &amp; Efficiency: Random Forest runs in 16.9 us with instant 0.63s training, while the MLP required 9.95s training and achieved slightly lower Macro F1 (98.73% vs 99.37%)."
        ),
        (
            "Q7: How could an Autoencoder or 1D-CNN be used for Zero-Day threat detection?",
            "An Autoencoder is an unsupervised neural network trained strictly on normal (Benign) traffic to compress flows into a low-dimensional bottleneck (encoder) and reconstruct them (decoder). When an unseen zero-day exploit arrives with abnormal telemetry, the network fails to reconstruct it, resulting in a high Reconstruction Error (Mean Squared Error). If MSE exceeds a calibrated threshold, the packet is flagged as an anomaly. A 1D-CNN can scan sequential packet payload bytes using 1D convolutional kernels to detect signature byte sequences regardless of packet alignment."
        ),
        (
            "Q8: How did you implement and evaluate your PyTorch 1D-CNN (CyberThreatCNN1D) model?",
            "In `src/train_deep_learning.py`, we implemented a custom PyTorch 1D-CNN (`CyberThreatCNN1D`) tailored for network flow vector sequence analysis:<br/><br/>(1) Layer Architecture: Input (batch, 1, 23 features) → Conv1D(1→32, kernel=3, pad=1) → BatchNorm1d(32) → LeakyReLU(0.1) → Dropout(0.2) → Conv1D(32→64, kernel=3, pad=1) → BatchNorm1d(64) → MaxPool1D(2) → Flatten(704) → Linear(704→128) → BatchNorm1d(128) → Dropout(0.3) → Linear(128→64) → Linear(64→6 Classes Softmax).<br/><br/>(2) Optimization: AdamW optimizer (lr=0.001, weight decay=1e-4) with ReduceLROnPlateau scheduler over 15 epochs on 17,146 real CIC-IDS2017 flows. Training loss decreased from 0.5114 down to 0.1912 (62.6% reduction) with a peak validation accuracy of 93.66% and final test accuracy of 89.35%."
        )
    ]

    for q, a in dl_qa:
        story.append(Paragraph(q, q_style))
        story.append(Paragraph(a, a_style))

    story.append(Spacer(1, 10))

    # ==========================================
    # SECTION 6: EXPLAINABLE AI (XAI) &amp; GENAI
    # ==========================================
    story.append(PageBreak())
    story.append(Paragraph("6. Explainable AI (XAI) &amp; Generative AI Viva Q&amp;A", h1_style))
    story.append(Paragraph(
        "Examiners love asking about interpretability because black-box models are unacceptable in regulated security operations:",
        body_style
    ))

    xai_qa = [
        (
            "Q1: What is the Black-Box problem in Security Operations Centers, and why is Explainable AI (XAI) needed?",
            "In high-stakes security operations, an alert stating 'Classification: DDoS (Confidence 99%)' without context creates alert fatigue and distrust. Tier-1 analysts cannot verify whether the classifier detected a genuine attack or flagged a false positive caused by benign server backups. Explainable AI bridges this trust deficit by mathematically showing the exact features and thresholds responsible for the alert, allowing rapid verification and compliant forensic reporting."
        ),
        (
            "Q2: What is SHAP, and how are Shapley Values calculated mathematically?",
            "SHAP (SHapley Additive exPlanations) is rooted in cooperative game theory (Lloyd Shapley, 1953). It treats feature values as 'players' in a game where the prediction is the 'payout'. The Shapley value phi_i allocates payout to feature i by computing its marginal contribution across all possible feature subsets S subset of F \\ {i}:<br/><br/><b>phi_i = sum_{S subset of F \\ {i}} [ |S|!(|F| - |S| - 1)! / |F|! ] * [ f(S union {i}) - f(S) ]</b><br/><br/>SHAP is uniquely guaranteed to satisfy three foundational properties: Local Accuracy (sum of feature attributions equals prediction difference from base rate), Missingness (missing features have zero attribution), and Consistency (if a model changes such that a feature contributes more, its attribution does not decrease)."
        ),
        (
            "Q3: Why did you use TreeExplainer instead of KernelExplainer or LIME?",
            "KernelExplainer and LIME (Local Interpretable Model-agnostic Explanations) are model-agnostic methods that rely on sampling perturbations, which makes them slow (several seconds per prediction) and non-deterministic. TreeExplainer (Lundberg et al., Nature Machine Intelligence 2020) is an exact polynomial-time algorithm tailored for decision trees that traverses tree pathways in O(T * L * D^2) time (where T=trees, L=leaves, D=depth). In our platform, TreeExplainer computes exact feature attributions in under 15 milliseconds, enabling real-time interactive rendering in the web browser."
        ),
        (
            "Q4: What is the role of Google Gemini 1.5 Flash in your platform, and how does it prevent hallucinations?",
            "Google Gemini serves as an automated Tier-1 incident response advisor. To prevent LLM hallucinations, we employ strict Grounded Prompt Engineering: the prompt includes the exact observed numerical flow telemetry, the MITRE ATT&amp;CK technique code, and system asset tags. Gemini is instructed to synthesize a concise, deterministic two-sentence briefing: Sentence 1 explains the root-cause anomaly in plain English, and Sentence 2 provides an actionable SOC triage playbook (e.g. 'Isolate IP 185.220.101.42 and verify web server auth logs'). If the API is unreachable or times out, the backend automatically falls back to pre-compiled local heuristic security playbooks."
        )
    ]

    for q, a in xai_qa:
        story.append(Paragraph(q, q_style))
        story.append(Paragraph(a, a_style))

    story.append(Spacer(1, 10))

    # ==========================================
    # SECTION 7: SOAR &amp; CYBERSECURITY VIVA PREP
    # ==========================================
    story.append(Paragraph("7. Cybersecurity, SOAR &amp; Defense-in-Depth Viva Q&amp;A", h1_style))
    story.append(Paragraph(
        "Examiners frequently evaluate your practical understanding of Security Orchestration, Automation, and Response:",
        body_style
    ))

    soar_qa = [
        (
            "Q1: What is the difference between SIEM, SOAR, IDS, and IPS?",
            "(1) IDS (Intrusion Detection System): Passively monitors traffic and triggers alerts when threats are identified (passive).<br/>(2) IPS (Intrusion Prevention System): In-line network appliance that actively drops packets or terminates connections when attacks occur (active).<br/>(3) SIEM (Security Information and Event Management): Centralized data aggregator collecting, correlating, and analyzing log telemetry across all network endpoints and firewalls.<br/>(4) SOAR (Security Orchestration, Automation, and Response): Automates response playbooks (e.g. automatically isolating a compromised host or blocking a firewall IP) to reduce Mean Time to Respond (MTTR). Our platform combines IDS analytics with automated SOAR containment."
        ),
        (
            "Q2: What is the MITRE ATT&CK Framework, and how did you map it in your project?",
            "MITRE ATT&CK (Adversarial Tactics, Techniques, and Common Knowledge) is a globally accessible knowledge base of adversary behaviors based on real-world observations. It breaks attacks down into Tactics (the adversary's technical goal, e.g., Discovery) and Techniques (how they achieve it). In our project:<br/><br/>- DDoS -> T1498 (Network Denial of Service)<br/>- PortScan -> T1046 (Network Service Discovery)<br/>- Brute Force -> T1110 (Brute Force Credentials)<br/>- Web Attack -> T1190 (Exploit Public-Facing Application)<br/>- Botnet -> T1071 (Application Layer Protocol C2)<br/><br/>Mapping every alert to MITRE ATT&CK enables standardized forensic reporting and cross-vendor firewall rule generation."
        ),
        (
            "Q3: How does your Active Host OS Containment work?",
            "When the analyst clicks 'Block Attacker IP' in the investigation drawer (or when automated containment triggers), the backend executes a direct OS-level packet drop rule: on Windows, it invokes `netsh advfirewall firewall add rule name='SOC_BLOCK_<IP>' dir=in action=block remoteip=<IP>`. It also dynamically renders exportable Linux `iptables -A INPUT -s <IP> -j DROP` and Suricata/Snort drop signatures, demonstrating end-to-end intrusion prevention."
        )
    ]

    for q, a in soar_qa:
        story.append(Paragraph(q, q_style))
        story.append(Paragraph(a, a_style))

    # Build the document
    doc.build(story, canvasmaker=NumberedCanvas)
    print(f"Document successfully created: {OUTPUT_PDF} ({os.path.getsize(OUTPUT_PDF):,} bytes)")

if __name__ == "__main__":
    build_pdf()
