#!/usr/bin/env python3
"""
Score predicted detections against ground truth.

Matching is technique-agnostic: an event is a true positive iff its
(src, rel, dst) triple is present in both ground truth and detections.
The MITRE technique label is treated as commentary, not as part of the key.

Usage:
    python3 evaluate.py --groundtruth groundtruth/groundtruth_blackenergy.yaml \
                        --detections  prediction/detections.yaml
"""

import argparse

import yaml


def load_events(path: str) -> list[dict]:
    with open(path) as f:
        return yaml.safe_load(f)["events"]


def key(e: dict) -> tuple:
    return (e["src"], e["rel"], e["dst"])


def metrics(gt: set, det: set) -> dict:
    tp = gt & det
    fp = det - gt
    fn = gt - det
    p  = len(tp) / len(det) if det else 0.0
    r  = len(tp) / len(gt)  if gt  else 0.0
    f1 = 2 * p * r / (p + r) if (p + r) else 0.0
    return dict(TP=len(tp), FP=len(fp), FN=len(fn), precision=p, recall=r, f1=f1,
                tp_edges=tp, fp_edges=fp, fn_edges=fn)


def by_rel(gt_events: list, det_events: list) -> dict:
    rels = {e["rel"] for e in gt_events} | {e["rel"] for e in det_events}
    out = {}
    for rel in sorted(rels):
        gt_keys  = {key(e) for e in gt_events  if e["rel"] == rel}
        det_keys = {key(e) for e in det_events if e["rel"] == rel}
        out[rel] = metrics(gt_keys, det_keys)
    return out


def print_metrics(m: dict, label: str = "overall"):
    print(f"\n  [{label}]")
    print(f"  Precision : {m['precision']:.3f}")
    print(f"  Recall    : {m['recall']:.3f}")
    print(f"  F1        : {m['f1']:.3f}")
    print(f"  TP={m['TP']}  FP={m['FP']}  FN={m['FN']}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--groundtruth", required=True)
    ap.add_argument("--detections",  required=True)
    ap.add_argument("--verbose",     action="store_true",
                    help="List FN/FP edges after the summary")
    args = ap.parse_args()

    gt_events  = load_events(args.groundtruth)
    det_events = load_events(args.detections)

    gt_keys  = {key(e) for e in gt_events}
    det_keys = {key(e) for e in det_events}

    print(f"\nGround truth : {len(gt_keys)} edges  ({args.groundtruth})")
    print(f"Detections   : {len(det_keys)} edges  ({args.detections})")

    print("\n" + "=" * 50)
    overall = metrics(gt_keys, det_keys)
    print_metrics(overall)

    print("\n" + "-" * 50)
    print("  Per-relation")
    for rel, m in by_rel(gt_events, det_events).items():
        print_metrics(m, rel)

    if args.verbose:
        if overall["fn_edges"]:
            print(f"\n  False Negatives ({len(overall['fn_edges'])}) — missed:")
            for src, rel, dst in sorted(overall["fn_edges"]):
                print(f"    {rel}  {src}  {dst}")
        if overall["fp_edges"]:
            print(f"\n  False Positives ({len(overall['fp_edges'])}) — spurious:")
            for src, rel, dst in sorted(overall["fp_edges"]):
                print(f"    {rel}  {src}  {dst}")


if __name__ == "__main__":
    main()

