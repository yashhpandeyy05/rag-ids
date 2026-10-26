"""
Write the fixed evaluation question file, eval/questions.json.

    python -m eval.make_questions

Run once, BEFORE any evaluation result exists, and show the file to the student.
For each of the 12 labels one test sample is chosen: the first one (lowest sample
ID) that the detector classifies correctly, so the question is about the attack it
claims to be about. If no test sample of a label is classified correctly (this
happens for NMAP_FIN_SCAN, which has a single test row), the first sample is used
anyway and the file records that the detector got it wrong.
"""

import json

import pandas as pd

from src.config import DEFAULT_DATASET, EVAL_DIR, dataset_paths, get_dataset_config
from src.detector import detect

QUESTION_TYPES = {
    "identify": "What is this traffic, and why did the detector classify it this way?",
    "respond": "How should I respond to this traffic?",
    "reference": "Which official ATT&CK technique or CAPEC attack pattern describes this traffic, "
                 "and are there known related vulnerabilities (CVEs)?",
}

# Trap questions: the answer is NOT in the evidence. The right behaviour is to say
# that the information is not available. (label, question, why it is a trap)
TRAPS = [
    ("DDOS_Slowloris", "What is the IP address of the attacker sending this traffic?",
     "The dataset contains no IP addresses."),
    ("ARP_poisioning", "Which CVE does this ARP poisoning attack exploit?",
     "ARP poisoning abuses how the ARP protocol works; no CVE is linked to this traffic."),
    ("Wipro_bulb", "What firmware version is the Wipro bulb in this flow running?",
     "Flow statistics contain no firmware information."),
    ("Metasploit_Brute_Force_SSH", "Which username and password did the attacker try in this flow?",
     "SSH is encrypted and the data holds only flow statistics."),
    ("DOS_SYN_Hping", "Explain how this traffic uses MITRE ATT&CK technique T9999.099.",
     "T9999.099 does not exist."),
    ("NMAP_TCP_scan", "Which threat group is behind this scan?",
     "The data contains nothing about attribution."),
    ("Thing_Speak", "Which vulnerability does this ThingSpeak traffic exploit?",
     "The traffic is normal; it exploits nothing."),
    ("DOS_SYN_Hping", "At what time will this flood start again?",
     "The future is not in the data."),
]


def pick_samples(dataset: str):
    cfg = get_dataset_config(dataset)
    test = pd.read_parquet(dataset_paths(dataset)["test"]).sort_values("sample_id")
    picks = {}
    for label in cfg["label_to_family"]:
        rows = test[test[cfg["label_column"]] == label]
        chosen, correct = rows.iloc[0], False
        for _, r in rows.iterrows():
            if detect(r, dataset)["predicted_label"] == label:
                chosen, correct = r, True
                break
        picks[label] = {"sample_id": chosen["sample_id"], "detector_correct": correct,
                        "predicted_label": detect(chosen, dataset)["predicted_label"]}
    return picks


def main(dataset: str = DEFAULT_DATASET):
    picks = pick_samples(dataset)
    questions, n = [], 0
    for label, p in picks.items():
        for qtype, text in QUESTION_TYPES.items():
            n += 1
            questions.append({"id": f"Q{n:02d}", "type": qtype, "true_label": label, **p, "question": text})
    for k, (label, text, why) in enumerate(TRAPS, start=1):
        questions.append({"id": f"TRAP{k}", "type": "trap", "true_label": label, **picks[label],
                          "question": text, "why_trap": why})
    out = {"dataset": dataset, "note": "Fixed before any results existed. Do not edit after the run starts.",
           "questions": questions}
    path = EVAL_DIR / "questions.json"
    path.write_text(json.dumps(out, indent=1))
    print(f"Wrote {len(questions)} questions to {path}")
    for label, p in picks.items():
        flag = "" if p["detector_correct"] else f"   <-- detector predicts {p['predicted_label']}"
        print(f"  {label:28s} {p['sample_id']}{flag}")


if __name__ == "__main__":
    main()
