const scenarios = {
  phishing: {
    id: "CASE #SS-1042",
    title: "Suspicious Microsoft 365 login alert",
    severity: "High",
    severityClass: "high",
    brief: "A user receives a message claiming their Microsoft 365 password will expire today. Minutes later, the security portal shows a successful login from a location the user does not recognize.",
    evidence: [
      ["Sender", "security-alert@micr0soft-support.com"],
      ["Login location", "Bucharest, RO"],
      ["User location", "California, US"],
      ["MFA prompt", "User says they did not approve it"]
    ],
    choices: [
      ["Reset the password later and continue monitoring", false],
      ["Disable active sessions, reset credentials, and verify MFA methods", true],
      ["Reply to the sender asking if the email is legitimate", false],
      ["Delete the email and close the ticket", false]
    ],
    good: "Correct. The account may already be compromised. Ending active sessions and resetting credentials contains immediate risk while you verify MFA and preserve the suspicious message for investigation.",
    bad: "That action leaves too much risk. When there is evidence of an unauthorized login, containment should happen immediately before normal cleanup.",
    impact: "High", urgency: "Immediate", confidence: "92%",
    risk: 92,
    note: "Containment comes before cleanup when an account may already be compromised."
  },
  ransomware: {
    id: "CASE #SS-2088",
    title: "Files suddenly renamed on workstation",
    severity: "Critical",
    severityClass: "critical",
    brief: "An accounting employee reports that multiple files now have unfamiliar extensions and a ransom note appeared on the desktop. The computer is still connected to the corporate network.",
    evidence: [
      ["Filename change", "Q3_budget.xlsx.locked"],
      ["Process", "unknown_update.exe"],
      ["Network", "Connected to shared drives"],
      ["Ransom note", "READ_ME_NOW.txt"]
    ],
    choices: [
      ["Disconnect the affected endpoint from the network", true],
      ["Restart the computer several times", false],
      ["Pay the ransom immediately", false],
      ["Delete the ransom note and continue working", false]
    ],
    good: "Correct. Isolating the endpoint helps stop possible lateral movement and further encryption. Evidence should then be preserved and the incident escalated according to the response plan.",
    bad: "That could increase damage or destroy useful evidence. The first priority is to isolate the affected system from the network.",
    impact: "Critical", urgency: "Immediate", confidence: "96%",
    risk: 96,
    note: "For suspected ransomware, isolate first. Do not erase evidence or reconnect the system until responders clear it."
  },
  wifi: {
    id: "CASE #SS-3154",
    title: "Unknown device on office Wi-Fi",
    severity: "Medium",
    severityClass: "medium",
    brief: "A network administrator notices a new device in the DHCP lease table at 11:47 PM. The MAC address is unfamiliar, and the hostname is blank.",
    evidence: [
      ["First seen", "11:47 PM"],
      ["Hostname", "Unknown"],
      ["VLAN", "Corporate Wi-Fi"],
      ["Traffic", "DNS + outbound HTTPS"]
    ],
    choices: [
      ["Identify the device and owner before blocking if risk is unclear", true],
      ["Ignore it because HTTPS traffic is normal", false],
      ["Reset every employee password", false],
      ["Power off the entire network", false]
    ],
    good: "Correct. Validate the device, user, and expected business purpose, then contain it if it is unauthorized. This avoids unnecessary disruption while still treating the event seriously.",
    bad: "That response is either too weak or too disruptive for the evidence available. Start by identifying and validating the device, then contain it if unauthorized.",
    impact: "Medium", urgency: "Prompt", confidence: "74%",
    risk: 64,
    note: "Not every unknown device is malicious. Good triage separates uncertainty from confirmed compromise."
  },
  usb: {
    id: "CASE #SS-4217",
    title: "Unapproved USB drive detected",
    severity: "High",
    severityClass: "high",
    brief: "Endpoint monitoring flags a removable USB drive connected to a finance workstation. The employee says they found the drive in the parking lot and plugged it in to see who owned it.",
    evidence: [
      ["Device type", "USB mass storage"],
      ["Workstation", "FIN-WS-014"],
      ["Source", "Found in parking lot"],
      ["Files opened", "Unknown"]
    ],
    choices: [
      ["Remove the drive, isolate if needed, and escalate for endpoint review", true],
      ["Open every file to identify the owner", false],
      ["Format the USB drive immediately", false],
      ["Copy the files to a shared drive for inspection", false]
    ],
    good: "Correct. Unknown removable media is a real malware risk. Stop interaction with the drive, preserve evidence, and review the endpoint before returning it to normal use.",
    bad: "That can execute malware, spread files, or destroy evidence. Stop interacting with the media and escalate the endpoint for review.",
    impact: "High", urgency: "Prompt", confidence: "88%",
    risk: 84,
    note: "Unknown removable media should never be explored on a production workstation."
  }
};

let current = "phishing";
let score = 0;
let solved = 0;
let streak = 0;
let bestStreak = 0;
const completed = new Set();

const els = {
  caseId: document.getElementById("caseId"),
  caseTitle: document.getElementById("caseTitle"),
  caseSeverity: document.getElementById("caseSeverity"),
  caseBrief: document.getElementById("caseBrief"),
  evidenceList: document.getElementById("evidenceList"),
  choices: document.getElementById("choices"),
  feedback: document.getElementById("feedback"),
  riskImpact: document.getElementById("riskImpact"),
  riskUrgency: document.getElementById("riskUrgency"),
  riskConfidence: document.getElementById("riskConfidence"),
  riskBar: document.getElementById("riskBar"),
  analystNote: document.getElementById("analystNote"),
  scoreMetric: document.getElementById("scoreMetric"),
  solvedMetric: document.getElementById("solvedMetric"),
  streakMetric: document.getElementById("streakMetric"),
  terminalText: document.getElementById("terminalText"),
  queueCount: document.getElementById("queueCount"),
};

function renderScenario(key){
  current = key;
  const s = scenarios[key];
  document.querySelectorAll(".scenario-card").forEach(c => c.classList.toggle("active", c.dataset.scenario === key));

  els.caseId.textContent = s.id;
  els.caseTitle.textContent = s.title;
  els.caseSeverity.textContent = s.severity;
  els.caseSeverity.className = "severity " + s.severityClass;
  els.caseBrief.textContent = s.brief;
  els.evidenceList.innerHTML = s.evidence.map(([a,b]) => `<div class="evidence-item"><span>${a}</span><span>${b}</span></div>`).join("");
  els.choices.innerHTML = "";
  s.choices.forEach(([text, correct], index) => {
    const btn = document.createElement("button");
    btn.className = "choice";
    btn.textContent = text;
    btn.onclick = () => choose(btn, correct, key);
    els.choices.appendChild(btn);
  });
  els.feedback.className = "feedback hidden";
  els.feedback.textContent = "";
  els.riskImpact.textContent = s.impact;
  els.riskUrgency.textContent = s.urgency;
  els.riskConfidence.textContent = s.confidence;
  els.riskBar.style.width = s.risk + "%";
  els.analystNote.textContent = s.note;
  resetChecks();
  terminal(`$ opened ${s.id.toLowerCase().replaceAll(" ","_")}\n$ evidence loaded\n$ awaiting first-response decision_`);
}

function choose(btn, correct, key){
  const s = scenarios[key];
  document.querySelectorAll(".choice").forEach(b => b.disabled = true);
  btn.classList.add(correct ? "correct" : "wrong");
  els.feedback.classList.remove("hidden");
  els.feedback.classList.add(correct ? "good" : "bad");
  els.feedback.textContent = correct ? s.good : s.bad;

  if(correct){
    document.getElementById("checkIdentify").checked = true;
    document.getElementById("checkContain").checked = true;
    document.getElementById("checkPreserve").checked = true;
    document.getElementById("checkCommunicate").checked = true;
    if(!completed.has(key)){
      score += 100;
      solved += 1;
      streak += 1;
      bestStreak = Math.max(bestStreak, streak);
      completed.add(key);
    }
    terminal(`$ decision accepted\n$ containment path selected\n$ analyst score +100\n$ case status: TRIAGED`);
  } else {
    streak = 0;
    terminal(`$ decision flagged\n$ residual risk remains\n$ review analyst note and retry next case`);
  }
  updateMetrics();
}

function updateMetrics(){
  els.scoreMetric.textContent = score;
  els.solvedMetric.textContent = solved;
  els.streakMetric.textContent = bestStreak;
  els.queueCount.textContent = `${4 - completed.size} open`;
}

function resetChecks(){
  ["checkIdentify","checkContain","checkPreserve","checkCommunicate"].forEach(id => document.getElementById(id).checked = false);
}

function terminal(text){
  els.terminalText.textContent = text;
}

document.querySelectorAll(".scenario-card").forEach(card => {
  card.addEventListener("click", () => renderScenario(card.dataset.scenario));
});

document.getElementById("startBtn").addEventListener("click", () => {
  document.querySelector(".workspace").scrollIntoView({behavior:"smooth"});
});

document.getElementById("randomBtn").addEventListener("click", () => {
  const keys = Object.keys(scenarios).filter(k => k !== current);
  renderScenario(keys[Math.floor(Math.random()*keys.length)]);
  document.querySelector(".workspace").scrollIntoView({behavior:"smooth"});
});

renderScenario("phishing");
