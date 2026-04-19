# Contributing to nftables-gui

First of all, thank you for considering contributing to nftables-gui 🚀

This project aims to provide a simple web interface to manage nftables rules in a more user-friendly way.

We welcome contributions of all kinds:

* Bug fixes 🐛
* UI improvements 🎨
* New features ✨
* Documentation improvements 📚
* Tests 🧪

---

# 🧭 Getting Started

## 1. Fork the repository

Click the "Fork" button on GitHub and clone your fork:

```bash
git clone https://github.com/YOUR_USERNAME/nftables-gui.git
cd nftables-gui
```

---

## 2. Create a virtual environment

```bash
python3 -m venv venv
source venv/bin/activate
```

---

## 3. Install dependencies

Make sure you install the required packages:

```bash
pip install -r requirements.txt
```

Also ensure system dependencies are installed:

* python3-nftables
* python3-hug

---

## 4. Run the project

You can use the provided script:

```bash
sudo chmod +x run.sh
sudo ./run.sh
```

Or run frontend/backend manually depending on your setup.

---

# 🧪 Running tests

From the `nftables-frontend` directory:

```bash
python -m pytest
python -m pytest --cov
python -m pytest --cov --cov-report=html
```

---

# 🐛 Reporting bugs

Before opening a bug report:

* Check if it already exists in Issues
* Try to reproduce it on the latest version

When reporting a bug, include:

* Steps to reproduce
* Expected behavior
* Actual behavior
* Your OS and Python version

---

# ✨ Making changes

## Recommended workflow:

1. Create a new branch

```bash
git checkout -b feature/my-feature
```

2. Make your changes

3. Run tests

4. Commit your changes

```bash
git add .
git commit -m "Add short description of change"
```

5. Push to your fork

```bash
git push origin feature/my-feature
```

6. Open a Pull Request on GitHub

---

# 📌 Pull Request guidelines

Please ensure:

* Code is clean and readable
* Your changes are focused (one feature per PR)
* Tests pass (if applicable)
* You explain what your PR does

---

# 🧠 Good first issues

If you're new to the project, look for issues labeled:

* `good first issue`
* `help wanted`

These are small and beginner-friendly tasks.

---

# ⚠️ Important notes

* Some parts of the project require sudo/root privileges due to nftables.
* Be careful when testing firewall rules.
* Do not commit sensitive or system-specific configurations.

---

# 🙌 Thank you

Every contribution helps improve nftables-gui and makes firewall configuration easier for everyone.
