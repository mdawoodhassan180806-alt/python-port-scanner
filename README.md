# Python Port Scanner

A simple multi-threaded TCP Port Scanner written in Python.

This project includes both:

- Command Line Interface (CLI)
- Tkinter Graphical User Interface (GUI)

The scanner is intended for learning purposes and should only be used on systems you own or have permission to test.

---

## Features

- Multi-threaded scanning
- Fast TCP connect scan
- Hostname resolution
- Service name detection
- Custom port ranges
- Custom timeout
- Adjustable thread count
- Progress display
- Stop scan button
- Clear output
- Cross-platform Python

---

## Project Structure

```
python-port-scanner/
│
├── scanner.py
├── scanner_gui.py
├── README.md
├── LICENSE
├── requirements.txt
├── .gitignore
└── screenshots/
```

---

## Requirements

- Python 3.8+
- Tkinter (GUI version)

Tkinter is included with most Python installations.

If missing on Kali Linux:

```bash
sudo apt install python3-tk
```

---

## Installation

Clone the repository

```bash
git clone https://github.com/yourusername/python-port-scanner.git
```

Enter the project

```bash
cd python-port-scanner
```

---

## Run CLI Version

```bash
python3 scanner.py 127.0.0.1
```

Example

```bash
python3 scanner.py 192.168.1.20 -p 1-1024
```

Specific ports

```bash
python3 scanner.py 192.168.1.20 -p 22,80,443
```

Scan all ports

```bash
python3 scanner.py 192.168.1.20 -p 1-65535
```

---

## Run GUI Version

```bash
python3 scanner_gui.py
```

---

## GUI Features

- Enter hostname/IP
- Select port range
- Configure timeout
- Configure thread count
- Live progress bar
- Open ports displayed
- Stop scan
- Clear output

---

## Example

```
Target:
127.0.0.1

Ports:
1-1024

Threads:
100
```

Output

```
[OPEN] Port 22 ssh
[OPEN] Port 80 http
```

---

## Screenshots

Add screenshots inside

```
screenshots/
```

Example

```
screenshots/gui.png
```

---

## Legal Notice

This software is intended **only for educational purposes**.

Only scan:

- Your own computers
- Your own servers
- Machines you have written permission to test

Unauthorized scanning may violate local laws.

---

## Future Improvements

- UDP scanning
- Export results to CSV
- Banner grabbing
- Dark mode
- Port filtering
- Scan history
- Save reports
- Theme support

---

## License

MIT License# python-port-scanner
