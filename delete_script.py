#!/usr/bin/env python3
"""
nuke_everything.py
Deletes ALL application data for the FastAPI app:
- Clears all tables in users.db
- Resets autoincrement sequences
- Optionally deletes chat_data/*.json files

Usage:
  python nuke_everything.py            # wipe DB only
  python nuke_everything.py --with-chats   # also delete chat_data JSONs
"""

import os
import sqlite3
import argparse
import glob

# --- Derive paths from the same layout as app.py ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_URL = os.path.join(BASE_DIR, "users.db")
CHAT_DATA_DIR = os.path.join(BASE_DIR, "chat_data")


def wipe_sqlite(db_path: str):
    if not os.path.exists(db_path):
        print(f"[info] Database file not found at {db_path}. Nothing to wipe.")
        return

    print(f"[info] Connecting to SQLite DB: {db_path}")
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        with conn:
            # Find all user tables (skip SQLite internal tables)
            rows = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';"
            ).fetchall()
            table_names = [r["name"] for r in rows]

            if not table_names:
                print("[info] No user tables found.")
            else:
                print(f"[info] Found tables: {', '.join(table_names)}")
                # Disable foreign keys to avoid constraints during purge (belt & suspenders)
                conn.execute("PRAGMA foreign_keys = OFF;")
                # Delete data from each table
                for t in table_names:
                    sql = f"DELETE FROM \"{t}\";"
                    conn.execute(sql)
                    print(f"[ok] Cleared table: {t}")

                # Try resetting AUTOINCREMENT counters (if table exists)
                try:
                    conn.execute("DELETE FROM sqlite_sequence;")
                    print("[ok] Reset AUTOINCREMENT sequences.")
                except sqlite3.OperationalError:
                    # sqlite_sequence may not exist; ignore
                    pass

            # Re-enable FK and VACUUM to reclaim space
            conn.execute("PRAGMA foreign_keys = ON;")
        # VACUUM must run outside explicit transaction
        conn.execute("VACUUM;")
        print("[ok] VACUUM complete.")
    finally:
        conn.close()
        print("[done] Database wipe finished.")


def wipe_chat_data(chat_dir: str):
    if not os.path.isdir(chat_dir):
        print(f"[info] Chat data directory not found at {chat_dir}. Skipping.")
        return
    files = glob.glob(os.path.join(chat_dir, "*.json"))
    if not files:
        print("[info] No chat JSON files to delete.")
        return
    deleted = 0
    for f in files:
        try:
            os.remove(f)
            deleted += 1
        except Exception as e:
            print(f"[warn] Failed to delete {f}: {e}")
    print(f"[ok] Deleted {deleted} chat JSON file(s) from {chat_dir}.")


def main():
    parser = argparse.ArgumentParser(description="Wipe ALL application data.")
    parser.add_argument("--with-chats", action="store_true",
                        help="Also delete chat_data/*.json files")
    args = parser.parse_args()

    print("==== DANGER ZONE ====")
    print("This operation will irreversibly delete ALL data from the app database.")
    print("======================")

    wipe_sqlite(DATABASE_URL)

    if args.with_chats:
        wipe_chat_data(CHAT_DATA_DIR)


if __name__ == "__main__":
    main()
