# 🧱 nftables-gui

<p align="center">
  <img src="https://wiki.nftables.org/wiki-nftables/netfilter-mini-flame.png?02eb9" alt="nftables logo" width="120"/>
</p>

<p align="center">
  <b>Web-based graphical interface to manage nftables firewall rules easily 🔥</b>
</p>




<p align="center">

[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=alegarsan11_nftables-gui&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=alegarsan11_nftables-gui)
  <img src="https://img.shields.io/badge/status-active-brightgreen" />
  <img src="https://img.shields.io/badge/python-3.x-blue" />

</p>


---

# 🚀 What is nftables-gui?

**nftables-gui** is a web interface that allows you to configure Linux `nftables` firewall rules in a simple and visual way.

Instead of writing complex firewall commands, you can:

* Create rules visually 🧩
* Manage existing rules 📋
* Deploy firewall configurations safely 🔒

---

# ✨ Features

* 🌐 Web-based interface
* 🧠 Simple rule creation system
* 🔥 Integration with nftables backend
* ⚙️ Supports rule execution via parser
* 🧪 Testing with pytest + coverage support
* 🐧 Designed for Linux systems

---

# 🖼️ Preview

![Preview](https://alegarsan11.vercel.app/nftables.png)

```text
Example:
[ Add Rule ]  [ Delete Rule ]
IP: 192.168.1.1
Port: 80
Action: ALLOW
```

---

# ⚙️ Requirements

Make sure you have:

* Python 3.x
* python3-nftables
* python3-hug
* virtualenv
* Linux system (required for nftables)

---

# 🧪 Installation & Setup

```bash
# Clone the repository
git clone https://github.com/alegarsan11/nftables-gui.git
cd nftables-gui
```

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate
```

```bash
# Install dependencies
pip install -r requirements.txt
```

---

# ▶️ Running the project

```bash
sudo chmod +x run.sh
sudo ./run.sh
```

---


## Default User Credentials
The default user credentials are as follows:
- Username: default
- Password: defaultpassword

---

# 🌐 Alternative deployments

## Apache

```bash
sudo chmod +x build.sh
sudo ./build.sh
```

Server runs on: `http://localhost:8080`

---

## Gunicorn

```bash
sudo apt install gunicorn gevent

# Backend
cd nftables-frontend
gunicorn -w 4 -b 0.0.0.0:4000 --worker-class gevent app:app

# Parser
cd ../nftables-parser
sudo hug -f main.py
```

---

# 🧪 Testing

```bash
pytest
pytest --cov
pytest --cov --cov-report=html
```

---

# 🧠 Project structure

```text
nftables-gui/
│── nftables-frontend/   # Web interface
│── nftables-parser/     # Backend logic
│── run.sh
│── build.sh
│── README.md
```

---

# 🤝 Contributing

We welcome contributions!

* Fix bugs 🐛
* Improve UI 🎨
* Add features ✨
* Improve documentation 📚

👉 See `CONTRIBUTING.md` for details.

---

# ⚠️ Security note

This project interacts directly with system firewall rules.

* Use with caution
* Requires sudo privileges
* Do not expose to public networks without proper security

---

# 🙌 Credits

Built with ❤️ for Linux networking and firewall management.
