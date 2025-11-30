# 🔐 Password Policy Analyzer (Compliance Focused)

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![Flask](https://img.shields.io/badge/Flask-2.0%2B-green)
![NIST](https://img.shields.io/badge/Standard-NIST%20800--63B-blue)
![License](https://img.shields.io/badge/License-MIT-green)

A compliance auditing tool that evaluates an organization's password policy against modern security standards (specifically NIST Special Publication 800-63B). It identifies outdated practices—like mandatory rotation and complexity rules—and provides actionable, educational recommendations.

## 🧐 The Problem

Many organizations still enforce "legacy" password policies (e.g., "Must change every 90 days", "Must have 1 uppercase, 1 symbol"). Research shows these rules actually **weaken** security by causing password fatigue, leading users to choose predictable patterns (e.g., `Summer2023!`, `Summer2023@`).

## 💡 The Solution

This tool acts as an automated auditor. You input your current policy settings, and it:
1.  **Grades** the policy (A-F) based on alignment with NIST 800-63B.
2.  **Flags** specific vulnerabilities (e.g., short length, forced rotation).
3.  **Educates** stakeholders on *why* the modern standard is better.

## 🚀 Features

- **NIST 800-63B Compliance Check**: Validates against the latest digital identity guidelines.
- **Interactive Audit Form**: Easy-to-use interface for inputting policy parameters.
- **Graded Reports**: Visual A/B/C/F grading system for quick risk assessment.
- **Educational Feedback**: Explains the "Why" behind every finding (e.g., why hints are bad).

## 🛠️ Installation

1.  **Clone the repository**:
    ```bash
    git clone https://github.com/CyberShuriken/password-policy-analyzer.git
    cd password-policy-analyzer
    ```

2.  **Install dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

## 💻 Usage

1.  **Start the Application**:
    ```bash
    python app.py
    ```

2.  **Access the Auditor**:
    Open `http://localhost:5000` in your browser.

3.  **Run an Audit**:
    - Enter a sample policy (e.g., Min Length: 8, Rotation: Yes).
    - Click **Analyze Policy**.
    - Review the generated report and recommendations.

## 🧠 Skills Demonstrated

- **GRC (Governance, Risk, and Compliance)**: Translating technical standards (NIST) into automated logic.
- **Risk Analysis**: Evaluating security controls and identifying gaps.
- **Web Development**: Building a functional tool with Python/Flask.
- **Security Communication**: Explaining complex security concepts to non-technical stakeholders clearly.

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
