# What SkillOrbit expects from you (Submission Guide)

## 1. The 7 deliverables

| # | Deliverable | Where it comes from |
|---|---|---|
| 1 | Source code | This folder |
| 2 | Project report | Write it using the outline in section 3 |
| 3 | PPT presentation | Use the slide plan in section 4 |
| 4 | GitHub repository | Push this folder (section 6) |
| 5 | Dashboard screenshots | Take them from the running dashboard, save in `screenshots/` |
| 6 | Demo video | Follow the script in section 5 |
| 7 | Traffic analysis reports | `python report.py` -> folders inside `reports/` |

## 2. How you are graded

Functionality 30% | Traffic analysis 25% | Security monitoring 20% | Dashboard/UI 10% |
Documentation 10% | Presentation 5%.
So: make sure real capture works, alerts fire, and the dashboard looks good. Documentation + slides are only 15%.

Scope rule from the brief: NO penetration testing, malware, unauthorised access or offensive tools.
Only test against your own VM (127.0.0.1). Say this in your report.

## 3. Project report outline (8-12 pages)

1. Title page (name, project title, date)
2. Introduction and objectives (copy from the brief, in your words)
3. Industry relevance (SOC, network admins, threat monitoring)
4. System architecture (diagram from README) and tech stack
5. Module descriptions: capture, monitoring, detection, dashboard, reports. For each: what it does, how, 1 screenshot
6. Database design (tables: packets, alerts, known_ips)
7. Detection rules with thresholds (table from README)
8. Testing and results: what traffic you generated, which alerts fired (screenshots)
9. Limitations and future work (ML anomaly detection, email alerts, IPv6, blocking)
10. Conclusion and learning outcomes
11. Appendix: key code snippets, GitHub link

## 4. PPT plan (10 slides)

1 Title | 2 Problem and objective | 3 Architecture | 4 Tech stack | 5 Packet capture and storage |
6 Traffic monitoring | 7 Detection rules | 8 Dashboard screenshots | 9 Alerts + report demo results | 10 Learnings, limitations, future work

## 5. Demo video script (3-5 minutes)

1. (20 s) Introduce the project and architecture slide.
2. (30 s) Start capture: `bash run_capture.sh`; show packets being saved.
3. (60 s) Open the dashboard: KPIs, packets/sec, protocol pie, top IPs, devices.
4. (60 s) Run `bash test_traffic.sh scan` and `ssh`, then `detector.py`; show the alerts in terminal and on the Alerts tab.
5. (30 s) Click "Generate report", open `security_report.html`.
6. (20 s) Show the GitHub repo and wrap up.
Record with OBS Studio or `kazam`.

## 6. GitHub

```bash
git init
git add .
git commit -m "Network Traffic Analyzer capstone"
git branch -M main
git remote add origin https://github.com/<your-username>/network-traffic-analyzer.git
git push -u origin main
```
(`traffic.db` and `venv/` are ignored by `.gitignore`.)

## 7. 5-day schedule

| Day | Goal |
|---|---|
| 1 | `bash setup.sh`; run `bash run_demo.sh`; run real capture and compare packet counts to Wireshark; read all code |
| 2 | Real capture + detector; trigger all rules with `test_traffic.sh`; tune `config.py` |
| 3 | Dashboard polish; take screenshots (with real data AND demo data); generate 2-3 reports |
| 4 | Write the project report; make the PPT |
| 5 | Record demo video; push to GitHub; test from a fresh clone; submit |

## 8. Be ready to explain (viva questions)

- What is a packet; what do TCP flags SYN/ACK/FIN mean; what is a port scan (many SYNs, many ports).
- Why root is needed for sniffing (raw sockets).
- Why SQLite and why WAL mode (dashboard reads while capture writes).
- How each detection rule works and its false positives (e.g. a busy download looks like a spike).
- Why median + MAD instead of mean + std (a spike inflates the mean and std itself).
- Why the scope is "monitoring only" (ethics and legality).
