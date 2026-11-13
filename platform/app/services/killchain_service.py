import re

KILL_CHAIN_PHASES = [
    "initial_access", "execution", "persistence", "privilege_escalation",
    "defense_evasion", "credential_access", "discovery", "lateral_movement",
    "collection", "exfiltration", "command_and_control", "impact",
]

_TECHNIQUE_TACTIC: dict[str, str] = {
    # initial_access
    "T1566": "initial_access", "T1190": "initial_access", "T1133": "initial_access",
    "T1200": "initial_access", "T1195": "initial_access", "T1189": "initial_access",
    "T1091": "initial_access", "T1078": "initial_access",
    # execution
    "T1059": "execution", "T1204": "execution", "T1053": "execution",
    "T1569": "execution", "T1106": "execution", "T1129": "execution",
    "T1047": "execution", "T1559": "execution",
    # persistence
    "T1547": "persistence", "T1543": "persistence", "T1546": "persistence",
    "T1574": "persistence", "T1505": "persistence",
    "T1176": "persistence", "T1137": "persistence", "T1197": "persistence",
    # privilege_escalation
    "T1548": "privilege_escalation", "T1134": "privilege_escalation",
    "T1055": "privilege_escalation", "T1484": "privilege_escalation",
    "T1611": "privilege_escalation",
    # defense_evasion
    "T1027": "defense_evasion", "T1036": "defense_evasion", "T1070": "defense_evasion",
    "T1562": "defense_evasion", "T1112": "defense_evasion", "T1140": "defense_evasion",
    "T1218": "defense_evasion", "T1497": "defense_evasion", "T1620": "defense_evasion",
    # credential_access
    "T1003": "credential_access", "T1110": "credential_access", "T1555": "credential_access",
    "T1056": "credential_access", "T1539": "credential_access", "T1552": "credential_access",
    "T1558": "credential_access",
    # discovery
    "T1083": "discovery", "T1057": "discovery", "T1082": "discovery",
    "T1016": "discovery", "T1049": "discovery", "T1033": "discovery",
    "T1087": "discovery", "T1046": "discovery", "T1135": "discovery",
    # lateral_movement
    "T1021": "lateral_movement", "T1534": "lateral_movement", "T1570": "lateral_movement",
    "T1550": "lateral_movement", "T1080": "lateral_movement",
    # collection
    "T1560": "collection", "T1005": "collection", "T1025": "collection",
    "T1074": "collection", "T1113": "collection", "T1125": "collection",
    "T1123": "collection", "T1119": "collection",
    # exfiltration
    "T1041": "exfiltration", "T1048": "exfiltration", "T1567": "exfiltration",
    "T1029": "exfiltration", "T1030": "exfiltration",
    # command_and_control
    "T1071": "command_and_control", "T1095": "command_and_control", "T1572": "command_and_control",
    "T1090": "command_and_control", "T1219": "command_and_control", "T1102": "command_and_control",
    "T1568": "command_and_control", "T1573": "command_and_control",
    # impact
    "T1486": "impact", "T1490": "impact", "T1498": "impact", "T1499": "impact",
    "T1529": "impact", "T1561": "impact", "T1485": "impact", "T1491": "impact",
}

_TECH_ID_RE = re.compile(r'\b(T\d{4})(?:\.\d+)?\b', re.IGNORECASE)


def analyze_kill_chain(attack_techniques: list[str]) -> dict:
    phase_techniques: dict[str, list[str]] = {p: [] for p in KILL_CHAIN_PHASES}

    for tech_str in attack_techniques:
        m = _TECH_ID_RE.search(tech_str)
        if not m:
            continue
        tid = m.group(1).upper()
        tactic = _TECHNIQUE_TACTIC.get(tid)
        if tactic:
            phase_techniques[tactic].append(tech_str)

    phases_covered = [p for p in KILL_CHAIN_PHASES if phase_techniques[p]]
    phases_missing = [p for p in KILL_CHAIN_PHASES if not phase_techniques[p]]
    completeness_score = round(len(phases_covered) / 12 * 100)

    if completeness_score >= 80:
        completeness_label = "full_chain"
    elif completeness_score >= 50:
        completeness_label = "partial_chain"
    else:
        completeness_label = "limited"

    chain_visualization = [
        {"phase": p, "covered": bool(phase_techniques[p]), "techniques": phase_techniques[p]}
        for p in KILL_CHAIN_PHASES
    ]

    has_initial = bool(phase_techniques["initial_access"])
    has_exec    = bool(phase_techniques["execution"])
    has_exfil   = bool(phase_techniques["exfiltration"])
    n_covered   = len(phases_covered)

    if has_initial and has_exec and has_exfil:
        operational_risk = "critical"
    elif n_covered >= 8:
        operational_risk = "high"
    elif n_covered >= 5:
        operational_risk = "medium"
    else:
        operational_risk = "low"

    return {
        "phases_covered":     phases_covered,
        "phases_missing":     phases_missing,
        "completeness_score": completeness_score,
        "completeness_label": completeness_label,
        "chain_visualization": chain_visualization,
        "operational_risk":   operational_risk,
    }
