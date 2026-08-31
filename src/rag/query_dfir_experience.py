import sys
import requests


QDRANT_URL = "http://localhost:6333"
OLLAMA_URL = "http://localhost:11434"

COLLECTION = "dfir_experience"

EMBED_MODEL = "nomic-embed-text"
LLM_MODEL = "qwen3:8b"

RETRIEVE_K = 10
CONTEXT_K = 6


SYSTEM_PROMPT = """
You are a senior DFIR investigator reasoning from historical case experience.

The CURRENT CASE contains only facts stated by the investigator.

The HISTORICAL CASES contain examples from previous investigations.

Your job is to transfer INVESTIGATIVE REASONING, not historical artifacts.

ABSOLUTE RULE:

Outside the section named "Historical Examples", NEVER recommend searching
for a specific tool, malware name, vulnerability, IOC, filename, process,
command, Event ID, IP address, domain, product name, or historical artifact
merely because it appears in the historical material.

GENERALIZE THE METHOD.

Example:

Historical case:
WMIC remote execution was attempted but was not observed on the target.
The actor later used PsExec and execution was observed on the destination.

GOOD recommendation:
"Correlate source-side remote-execution attempts with destination-side
execution evidence. Treat an attempt as unconfirmed until target-side
evidence demonstrates execution."

BAD recommendation:
"Check for WMIC and PsExec."

Another example:

Historical case:
Privileged credentials were used through RDP to access additional servers.

GOOD recommendation:
"Correlate privileged authentication from the suspected source host with
destination systems and subsequent activity to identify scope expansion."

BAD recommendation:
"Look for RDP and domain-admin credentials."

Historical-specific names may appear ONLY inside:

Historical Examples

They must never be presented as suspected current-case activity.

Do not add Event IDs, paths, commands, artifacts, tools, log sources,
techniques, or technical facts from your own knowledge.

If the historical material does not support a recommendation, say so.

Required structure:

1. Current Facts
2. Investigation Sequence
3. Evidence Relationships to Test
4. Scope Expansion
5. Historical Examples
6. Not Yet Known
"""


def embed(text):

    response = requests.post(
        f"{OLLAMA_URL}/api/embeddings",
        json={
            "model": EMBED_MODEL,
            "prompt": text,
        },
        timeout=120,
    )

    response.raise_for_status()

    return response.json()["embedding"]



def rerank_for_question(query, results):
    """
    Apply a small deterministic rerank when the investigator
    explicitly asks about activity BEFORE ransomware impact.

    Historical text and Qdrant scores are not modified.
    Only result ordering is adjusted.
    """

    query_lower = query.lower()

    appliance_query_signals = (
        "network appliance",
        "network infrastructure appliance",
        "network infrastructure",
        "network device",
        "infrastructure device",
        "router",
        "switch",
        "firewall appliance",
        "network controller",
    )

    if any(
        signal in query_lower
        for signal in appliance_query_signals
    ):
        appliance_terms = (
            "network appliance",
            "network device",
            "controller",
            "sd-wan",
            "router",
            "switch",
            "firewall",
            "ssh",
            "peering",
            "configuration",
            "administrative account",
            "admin account",
            "device configuration",
            "control plane",
        )

        reranked = []

        for item in results:

            adjusted = dict(item)

            payload = adjusted.get(
                "payload",
                {},
            )

            searchable = " ".join(
                [
                    str(payload.get("text", "")),
                    str(payload.get("heading", "")),
                    str(payload.get("phase", "")),
                    str(payload.get("case", "")),
                ]
            ).lower()

            original_score = float(
                adjusted.get(
                    "score",
                    0.0,
                )
            )

            matches = sum(
                1
                for term in appliance_terms
                if term in searchable
            )

            bonus = min(
                matches * 0.025,
                0.150,
            )

            adjusted["_original_score"] = original_score
            adjusted["_rerank_score"] = original_score + bonus

            reranked.append(adjusted)

        reranked.sort(
            key=lambda item: item["_rerank_score"],
            reverse=True,
        )

        return reranked

    preimpact_signals = (
        "no ransomware",
        "ransomware has not",
        "ransomware hasn't",
        "before ransomware",
        "before impact",
        "prior to ransomware",
        "prior to impact",
        "ransomware precursor",
        "ransomware precursors",
        "progressing toward ransomware",
        "progressing to ransomware",
        "leading to ransomware",
        "escalation before impact",
    )

    if not any(
        signal in query_lower
        for signal in preimpact_signals
    ):
        return results

    phase_bonus = {
        "credential_access": 0.055,
        "privilege_escalation": 0.050,
        "lateral_movement": 0.050,
        "defense_evasion": 0.045,
        "discovery": 0.040,
        "collection": 0.040,
        "persistence": 0.035,
        "command_and_control": 0.035,
        "execution": 0.025,
        "initial_access": 0.015,
        "impact": -0.080,
    }

    reranked = []

    for item in results:

        adjusted = dict(item)

        payload = adjusted.get(
            "payload",
            {},
        )

        phase = str(
            payload.get(
                "phase",
                "",
            )
        ).lower()

        original_score = float(
            adjusted.get(
                "score",
                0.0,
            )
        )

        adjusted["_original_score"] = (
            original_score
        )

        adjusted["_rerank_score"] = (
            original_score
            + phase_bonus.get(
                phase,
                0.0,
            )
        )

        reranked.append(
            adjusted
        )

    reranked.sort(
        key=lambda item: item[
            "_rerank_score"
        ],
        reverse=True,
    )

    return reranked

def retrieve(query):

    vector = embed(query)

    response = requests.post(
        (
            f"{QDRANT_URL}/collections/"
            f"{COLLECTION}/points/search"
        ),
        json={
            "vector": vector,
            "limit": RETRIEVE_K * 12,
            "with_payload": True,
        },
        timeout=60,
    )

    response.raise_for_status()

    results = response.json()["result"]

    return rerank_for_question(
        query,
        results,
    )[:RETRIEVE_K]


def select_context(results):

    selected = []
    seen = set()

    for item in results:

        payload = item.get(
            "payload",
            {},
        )

        text = payload.get(
            "text",
            "",
        ).strip()

        if not text:
            continue

        key = (
            payload.get("case"),
            payload.get("phase"),
            payload.get("window_order"),
        )

        if key in seen:
            continue

        seen.add(key)

        # Skip very weak tiny fragments.
        if len(text) < 300:
            continue

        selected.append(item)

        if len(selected) >= CONTEXT_K:
            break

    return selected


def build_context(results):

    blocks = []

    for index, item in enumerate(
        results,
        start=1,
    ):

        payload = item["payload"]

        block = (
            f"[HISTORICAL CASE {index}]\n"
            f"Case: {payload.get('case')}\n"
            f"Source: {payload.get('source')}\n"
            f"DFIR Phase: {payload.get('phase')}\n"
            f"Section: {payload.get('heading')}\n"
            f"Similarity: {item.get('score', 0):.4f}\n\n"
            f"{payload.get('text', '')}"
        )

        blocks.append(block)

    return "\n\n" + ("\n\n" + ("-" * 70) + "\n\n").join(blocks)


def ask_qwen(question, context):

    user_prompt = f"""
CURRENT CASE / INVESTIGATOR QUESTION:

{question}


HISTORICAL DFIR EXPERIENCE:

{context}


Use the historical material as investigative experience only.

Do not transform historical case facts into facts about the current case.

Recommend a defensible investigation approach grounded in the supplied
historical experience and the current-case facts.
"""

    response = requests.post(
        f"{OLLAMA_URL}/api/chat",
        json={
            "model": LLM_MODEL,

            "messages": [
                {
                    "role": "system",
                    "content": SYSTEM_PROMPT,
                },
                {
                    "role": "user",
                    "content": user_prompt,
                },
            ],

            "stream": False,
            "think": False,

            "options": {
                "temperature": 0,
                "num_ctx": 8192,
                "num_predict": 1400,
            },
        },
        timeout=900,
    )

    response.raise_for_status()

    return response.json()[
        "message"
    ]["content"]



HISTORICAL_ONLY_TERMS = [
    "zero.exe",
    "psexec",
    "wmic",
    "cobalt strike",
    "metasploit",
    "zerologon",
    "cve-2020-1472",
    "rustscan",
    "nmap",
]


def validate_grounding(answer, question):
    """
    Historical-specific entities may appear only in section 5:
    Historical Examples.

    If they appear in sections 1-4, the answer fails.
    """

    lower_answer = answer.lower()
    lower_question = question.lower()

    marker = "5. **historical examples**"

    pos = lower_answer.find(marker)

    if pos == -1:
        marker = "5. historical examples"
        pos = lower_answer.find(marker)

    if pos == -1:
        return False, [
            "Historical Examples section not found"
        ]

    recommendation_part = lower_answer[:pos]

    violations = []

    for term in HISTORICAL_ONLY_TERMS:

        if term in lower_question:
            continue

        if term in recommendation_part:
            violations.append(term)

    if violations:
        return False, violations

    return True, []


def correct_grounding_answer(question, context, answer, violations):
    """
    One corrective Qwen pass after deterministic grounding failure.
    """

    violation_text = ", ".join(violations)

    correction_prompt = f"""
The previous answer FAILED deterministic grounding validation.

CURRENT CASE:

{question}


HISTORICAL DFIR EXPERIENCE:

{context}


PREVIOUS INVALID ANSWER:

{answer}


VALIDATOR VIOLATIONS:

{violation_text}


Rewrite the answer.

MANDATORY CORRECTION:

The listed historical-specific entities appeared in current-case
recommendations even though the investigator did not establish them.

Remove those historical-specific entities from:

1. Current Facts
2. Investigation Sequence
3. Evidence Relationships to Test
4. Scope Expansion

Generalize them into investigation principles instead.

Example:

BAD:
"Check for PsExec and WMIC."

GOOD:
"Correlate source-side remote-execution attempts with destination-side
execution evidence and do not treat an attempt as successful movement
without target-side corroboration."

Historical-specific names may remain ONLY in:

5. Historical Examples

Do not introduce new Event IDs, tools, paths, commands, products,
vulnerabilities, malware, IOCs, or techniques.

Return the complete corrected answer using exactly these sections:

1. Current Facts
2. Investigation Sequence
3. Evidence Relationships to Test
4. Scope Expansion
5. Historical Examples
6. Not Yet Known
"""

    response = requests.post(
        f"{OLLAMA_URL}/api/chat",
        json={
            "model": LLM_MODEL,
            "messages": [
                {
                    "role": "system",
                    "content": SYSTEM_PROMPT,
                },
                {
                    "role": "user",
                    "content": correction_prompt,
                },
            ],
            "stream": False,
            "think": False,
            "options": {
                "temperature": 0,
                "num_ctx": 8192,
                "num_predict": 1000,
            },
        },
        timeout=900,
    )

    response.raise_for_status()

    return response.json()["message"]["content"]

def main():

    if len(sys.argv) < 2:

        print(
            'Usage: python query_dfir_experience.py "question"'
        )

        sys.exit(1)

    question = " ".join(
        sys.argv[1:]
    )

    print("=" * 78)
    print("DFIR EXPERIENCE RAG")
    print("=" * 78)

    print()
    print(
        f"Question: {question}"
    )

    print()
    print(
        "Retrieving historical experience..."
    )

    results = retrieve(question)

    selected = select_context(
        results
    )

    print(
        f"Retrieved : {len(results)}"
    )

    print(
        f"Selected  : {len(selected)}"
    )

    print()

    for index, item in enumerate(
        selected,
        start=1,
    ):

        payload = item["payload"]

        print(
            f"[{index}] "
            f"{item['score']:.4f} | "
            f"{payload.get('phase')} | "
            f"window "
            f"{payload.get('window_order')}"
        )

    context = build_context(
        selected
    )

    print()
    print(
        f"Sending {len(selected)} historical "
        f"experience windows to {LLM_MODEL}..."
    )

    answer = ask_qwen(
        question,
        context,
    )

    valid, violations = validate_grounding(
        answer,
        question,
    )

    if not valid:

        print()
        print("=" * 78)
        print("GROUNDING VALIDATION: FAILED")
        print("=" * 78)
        print()

        for violation in violations:
            print(
                f"Historical artifact leaked into "
                f"current-case guidance: {violation}"
            )

        print()
        print("Attempting one corrective generation...")

        answer = correct_grounding_answer(
            question,
            context,
            answer,
            violations,
        )

        valid, violations = validate_grounding(
            answer,
            question,
        )

        if not valid:

            print()
            print("=" * 78)
            print("CORRECTIVE GROUNDING VALIDATION: FAILED")
            print("=" * 78)
            print()

            for violation in violations:
                print(
                    f"Historical artifact still leaked: "
                    f"{violation}"
                )

            print()
            print(
                "Answer suppressed after corrective "
                "generation failed grounding validation."
            )

            sys.exit(2)

        print()
        print("Corrective grounding validation: PASS")
    print()
    print("=" * 78)
    print("DFIR INVESTIGATION GUIDANCE")
    print("=" * 78)
    print()
    print(answer)


if __name__ == "__main__":
    main()











