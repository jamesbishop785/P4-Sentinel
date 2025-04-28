# 🛡️ P4-Sentinel: A Stateful Rate Limiter for Real-Time DDoS Mitigation

_Dissertation Project — James Bishop_  
_Supervised by Dr. Ahmed Basil_  
_April 2025_

---

## 📚 Info

This project addresses the research gap by implementing a **stateful rate limiter** within a **P4 data plane** to effectively detect and mitigate DDoS attacks, while integrating a **real-time monitoring solution** through a **Python-based control plane** using **Thrift-API**.

A programmable data plane was designed using the **P4 language** on the **BMv2 target** to track per-flow packet rates and enforce a predefined threshold limit. Additionally, a Python-based control plane was developed to monitor network traffic in real-time, log attack activity, and provide alerts through Thrift interface access to data plane metrics.  

The system was tested against multiple DDoS attack scenarios, including SYN floods, ICMP floods, UDP floods, Slowloris, burst attacks, and MAC spoofing attacks.

Key results:

- **Mitigation accuracy up to 99.8%**
- **Low-latency real-time response**
- **Resilience under scaled testbed conditions**

The findings demonstrate the potential of a **P4-based stateful solution integrated with live control plane monitoring** for high-performance, programmable network security systems.

---
