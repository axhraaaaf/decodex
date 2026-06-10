# DecodeX v2

**DecodeX** is a professional-grade cybersecurity toolkit and terminal user interface (TUI) designed for malware analysis, data decoding, and offensive security research. It wraps a powerful Python analysis engine in a polished, high-performance Go-based dashboard.

---

## 🚀 Features

### 🖥️ Professional TUI (v2)
- **Interactive Dashboard**: Modern, navigable interface built with Go and Bubble Tea.
- **Split-Screen Analysis**: View file triage results, risk scores, and technical indicators in real-time.
- **Neon Cyberpunk Aesthetic**: High-visibility styling using Lip Gloss.

### 🔍 Advanced Malware Triage
- **Deep PE Inspection**: Powered by `pefile` for industrial-grade static analysis.
- **Imphash Support**: Calculate import hashes for malware family attribution.
- **Suspicious Indicator Detection**: Automatic detection of RWX sections, suspicious imports (IAT), and high-entropy payloads.
- **Overlay Detection**: Identify hidden data appended to binaries.

### 🛠️ Core Tools
- **Auto-Decode Engine**: Multi-branch decoding with readability scoring.
- **Encoding/Decoding**: Base64, Hex, and advanced XOR (brute-force support).
- **Risk Scoring**: Heuristic-based risk engine with visual indicators.

---

## 📦 Installation & Setup

### Local Setup (Go + Python)
### 1. Global Installation (Recommended)
To use the `decodex` command from anywhere:
```bash
git clone https://github.com/YOUR_USERNAME/decodeX.git
cd decodeX
pip install .
```
Now you can simply run `decodex` in your terminal!

### 2. Manual Installation
```bash
pip install -r requirements.txt
python main.py --help
```
3. **Build the TUI**:
   ```bash
   go build -o decodeX main.go
   ```
4. **Run**:
   ```bash
   ./decodeX
   ```

### Running with Docker
You can run DecodeX as a containerized tool without installing local dependencies.

1. **Build the image**:
   ```bash
   docker build -t decodex .
   ```
2. **Run the TUI (interactive mode)**:
   ```bash
   docker run -it --rm -v $(pwd):/app decodex
   ```

---

## 🛠️ Development

### Project Structure
- `main.go`: Entry point for the Go TUI.
- `framework/`: Backend framework and plugin engine.
- `core/`: Core analysis and decoding logic.
- `plugins/`: Pluggable analysis modules (PE, XOR, etc.).
- `Dockerfile`: Multi-stage build for Go/Python hybrid environment.
- `.github/workflows/`: CI/CD for automated builds.

---

## 🤝 Contribution & Integration
DecodeX is designed to be extensible. You can add new analysis capabilities by creating a new plugin in the `plugins/` directory.

---

## ⚖️ Disclaimer
This tool is intended for **educational and ethical cybersecurity use only**. Use it only on systems and data you are authorized to analyze.

---

**Developed by Achraaf | Enhanced by Antigravity AI**