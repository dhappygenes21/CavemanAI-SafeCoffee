☕ **SafeCoffee v3**

***Dynamic Network Defense by CavemanAI***

**SafeCoffee v3** is a proactive security application designed to protect users on public or untrusted Wi-Fi networks. While powered by the **D-ARCai** engine, it is branded under **CavemanAI** to ensure that even non-technical users can participate in the "AI Revolution" by securing their digital perimeter with a single click.

🛡️ **Core Features**

	**•	DeepShield Monitoring:** Constant surveillance of the ARP table and 802.11 frames to detect MITM (Man-in-the-Middle) attacks.

	**•	Heartbeat Verification:** A background pulse that verifies the gateway's identity every 30 seconds to ensure your traffic isn't being rerouted.

	**•	Retaliatory Counter-Pulse:** Automatically disrupts an attacker's connection using de-authentication frames if they attempt to spoof your gateway.

	**•	Terminal Panic Mode:** An "emergency brake" that immediately shuts down your network interface to prevent data exfiltration.

	**•	One-Click Recovery:** A specialized "Recover Connection" feature that re-engages the hardware and restarts the Linux Network Manager automatically.

🚀 **New: The Recovery Workflow**

In version 2.1, we've simplified the post-attack workflow. If you use the **Terminal Panic** button to air-gap your machine:

	1	The status will change to **OFFLINE**.

	2	Simply click **RECOVER CONNECTION**.

	3	The system will re-enable the Wi-Fi adapter and nudge the **Network Manager** to reconnect to your preferred network—no terminal commands required.

🛠️ **Requirements & Environment**

To maintain uniformity across the **D-ARCai** ecosystem, this tool requires **Python 3.12** and the **PySide6** GUI backbone.

**Component**  
**Requirement**  
**Operating System**  
Kali Linux (Persistent USB recommended)  
**Python Version**  
3.12+  
**Core Libraries**  
PySide6, scapy  
**Privileges**  
Root / Sudo (Required for raw packet injection)

⚠️ **Troubleshooting (Kali Linux Specifics)**

**Issue**  
**Solution**  
**Qt "xcb" Plugin Error**  
Run export QT\_QPA\_PLATFORM=xcb before launching.  
**Adapter Not Found**  
Ensure your USB adapter is recognized (check iwconfig).  
**Recovery Fails**  
If the button doesn't work, manually run sudo systemctl restart NetworkManager.

📜 **Brand Philosophy: CavemanAI**

"Smart tech for the modern hunter-gatherer."

The goal of SafeCoffee is **ease of use**. We take the complex research concepts from **D-ARCai** and package them into tools that allow any user to protect their daily-carry laptops without needing a degree in cybersecurity.

⚓ **CavemanAI is using the following open-source technologies:**

	**•	\[PySide6\]([https://doc.qt.io](https://doc.qt.io)) \-** Qt for Python GUI framework **(LGPLv3)**

	**•	\[Scapy\] ([https://scapy.net](https://scapy.net)) \-** Interactive packet manipulation and network discovery (GPL v2)

	**•	\[Python Standard Library\] ([https://docs.python.org](https://docs.python.org)) \-** Core system, threading, and OS integrations.

