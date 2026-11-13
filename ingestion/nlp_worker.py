#!/usr/bin/env python3
"""NLP worker daemon.

Loads all heavy models once at startup (spaCy, sumy, OpenAI client), then polls
MongoDB for pending scrape jobs and processes them through the NLP pipeline.

Usage:
    python3 nlp_worker.py

Run as many instances as you need concurrent NLP threads, but one is usually
enough since the bottleneck is the GPT-4o API call, not CPU.
"""
import gc
import multiprocessing as mp
import signal
import time
from datetime import datetime

from pymongo import MongoClient
from modules.jobQueue import _get_col as _get_queue_col
from modules.nlp import nlp_scan   # heavy imports (spaCy, sumy) happen here once
from modules.articleValidator import OpenAIQuotaExhausted

_running = True
_JOB_TIMEOUT_SECONDS = 120

# spawn (not fork): dbMongo.py keeps a module-level MongoClient open at import
# time. fork() would copy that live socket into the child, and PyMongo
# explicitly warns against reusing a connection across a fork — the inherited
# socket state can silently hang, which is exactly the symptom this timeout
# guard exists to catch. spawn costs a few extra seconds per job (fresh
# interpreter re-imports spaCy/sumy/mongo client) but has no shared state.
_mp_ctx = mp.get_context("spawn")


def _run_job(article, script_name, result_queue):
    """Runs in a child process so a stuck/CPU-pegged job (e.g. a regex
    catastrophic-backtrack in the tokenizer) can be hard-killed on timeout —
    a thread can't be killed and won't even honor SIGINT while the GIL is
    monopolized by a pure-C loop."""
    try:
        result = nlp_scan(article, script_name)
        result_queue.put(("ok", result))
    except OpenAIQuotaExhausted as e:
        result_queue.put(("quota_exhausted", str(e)))
    except Exception as e:
        result_queue.put(("error", str(e)))


def _handle_signal(sig, frame):
    global _running
    print(f"Worker shutting down (signal {sig})...")
    _running = False


signal.signal(signal.SIGTERM, _handle_signal)
signal.signal(signal.SIGINT, _handle_signal)


def main():
    global _running
    mongo_client, col = _get_queue_col()
    
    # Reset jobs left in "processing" state from a previous crashed worker
    reset_result = col.update_many(
        {"status": "processing"},
        {"$set": {"status": "pending"}},
    )
    if reset_result.modified_count:
        print(f"Reset {reset_result.modified_count} stale processing job(s) to pending.")

    print("NLP worker ready. Waiting for jobs...")

    try:
        while _running:
            job = col.find_one_and_update(
                {"status": "pending"},
                {"$set": {"status": "processing", "started_at": datetime.utcnow()}},
                sort=[("created_at", 1)],
                return_document=True,
            )
            print(job)

            if not job:
                time.sleep(2)
                continue

            title = job['article'].get('title', '')[:80]
            print(f"Processing: {title}")

            result_queue = _mp_ctx.Queue()
            proc = _mp_ctx.Process(
                target=_run_job,
                args=(job['article'], job['script_name'], result_queue),
            )
            proc.start()
            proc.join(timeout=_JOB_TIMEOUT_SECONDS)

            if proc.is_alive():
                print(f"Job exceeded {_JOB_TIMEOUT_SECONDS}s — killing stuck worker process (pid {proc.pid})")
                proc.kill()   # SIGKILL: thread-level timeouts can't stop a GIL-hogging C loop, a process can
                proc.join()
                col.update_one(
                    {"_id": job['_id']},
                    {"$set": {"status": "failed", "error": f"nlp_scan exceeded {_JOB_TIMEOUT_SECONDS}s timeout (process killed)", "failed_at": datetime.utcnow()}},
                )
            else:
                kind, payload = result_queue.get() if not result_queue.empty() else ("error", "worker process exited without a result")
                if kind == "ok":
                    new_status = "filtered" if payload is None else "completed"
                    col.update_one(
                        {"_id": job['_id']},
                        {"$set": {"status": new_status, "completed_at": datetime.utcnow()}},
                    )
                elif kind == "quota_exhausted":
                    print(f"[FATAL] {payload}")
                    print("OpenAI credit exhausted — requeue job and stop worker.")
                    col.update_one(
                        {"_id": job['_id']},
                        {"$set": {"status": "pending", "error": payload}},
                    )
                    _running = False
                else:
                    print(f"Job failed: {payload}")
                    col.update_one(
                        {"_id": job['_id']},
                        {"$set": {"status": "failed", "error": payload, "failed_at": datetime.utcnow()}},
                    )
            result_queue.close()
            gc.collect()
    finally:
        mongo_client.close()
        print("Worker stopped.")


if __name__ == '__main__':
    main()
