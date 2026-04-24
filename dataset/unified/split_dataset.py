"""
GATE80 - Stratified Train/Test Split
dataset/unified/split_dataset.py

Splits gate80_dataset.csv into train and test sets using stratified
sampling to preserve the class distribution in both sets.

Split: 80% train / 20% test
Stratified on: label (0=normal, 1=abnormal)

Reference: ScienceDirect anomaly detection paper (2023) -- 80/20 split
is standard for network anomaly detection ML evaluation.

Input:  dataset/unified/output/gate80_dataset.csv
Output: dataset/unified/output/gate80_train.csv
        dataset/unified/output/gate80_test.csv

Run:
    python dataset/unified/split_dataset.py
"""

import csv
import os
import random
from collections import defaultdict

INPUT_FILE  = "dataset/unified/output/gate80_dataset.csv"
TRAIN_FILE  = "dataset/unified/output/gate80_train.csv"
TEST_FILE   = "dataset/unified/output/gate80_test.csv"

TRAIN_RATIO = 0.80
RANDOM_SEED = 42  # fixed seed for reproducibility


def main():
    if not os.path.exists(INPUT_FILE):
        print(f"[ERROR] Input not found: {INPUT_FILE}")
        return

    print(f"[1/3] Loading {INPUT_FILE}...")
    with open(INPUT_FILE, newline="", encoding="utf-8") as f:
        reader     = csv.DictReader(f)
        fieldnames = reader.fieldnames
        rows       = list(reader)

    print(f"      {len(rows):,} sessions loaded.")

    print("[2/3] Stratifying by label...")
    by_label = defaultdict(list)
    for row in rows:
        by_label[row["label"]].append(row)

    random.seed(RANDOM_SEED)

    train_rows, test_rows = [], []

    for label, label_rows in sorted(by_label.items()):
        random.shuffle(label_rows)
        n_train = int(len(label_rows) * TRAIN_RATIO)
        train_rows.extend(label_rows[:n_train])
        test_rows.extend(label_rows[n_train:])

    random.shuffle(train_rows)
    random.shuffle(test_rows)

    print("[3/3] Writing split files...")

    with open(TRAIN_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(train_rows)

    with open(TEST_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(test_rows)

    train_normal   = sum(1 for r in train_rows if r["label"] == "0")
    train_abnormal = sum(1 for r in train_rows if r["label"] == "1")
    test_normal    = sum(1 for r in test_rows  if r["label"] == "0")
    test_abnormal  = sum(1 for r in test_rows  if r["label"] == "1")

    print(f"\n{'='*60}")
    print(f"  Train : {len(train_rows):,} sessions")
    print(f"    normal   : {train_normal:,} ({train_normal/len(train_rows)*100:.1f}%)")
    print(f"    abnormal : {train_abnormal:,} ({train_abnormal/len(train_rows)*100:.1f}%)")
    print(f"\n  Test  : {len(test_rows):,} sessions")
    print(f"    normal   : {test_normal:,} ({test_normal/len(test_rows)*100:.1f}%)")
    print(f"    abnormal : {test_abnormal:,} ({test_abnormal/len(test_rows)*100:.1f}%)")
    print(f"\n  Seed  : {RANDOM_SEED} (fixed for reproducibility)")
    print(f"\n  Output:")
    print(f"    {TRAIN_FILE}")
    print(f"    {TEST_FILE}")
    print(f"\n  Next step: python dataset/unified/train_model.py")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()