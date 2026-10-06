"""Metrics + confusion-matrix plot."""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix


def evaluate(y_true, y_pred):
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    return {"accuracy": accuracy_score(y_true, y_pred), "precision": precision_score(y_true, y_pred, zero_division=0),
            "recall": recall_score(y_true, y_pred, zero_division=0), "f1": f1_score(y_true, y_pred, zero_division=0),
            "TP": int(tp), "TN": int(tn), "FP": int(fp), "FN": int(fn)}


def plot_confusion_matrix(m, title, path):
    fig, ax = plt.subplots(figsize=(4, 4))
    grid = [[m["TN"], m["FP"]], [m["FN"], m["TP"]]]
    ax.imshow(grid, cmap="Blues")
    for i in range(2):
        for j in range(2):
            ax.text(j, i, grid[i][j], ha="center", va="center", fontsize=16)
    ax.set_xticks([0, 1], ["Legit", "Phishing"]); ax.set_yticks([0, 1], ["Legit", "Phishing"])
    ax.set_xlabel("Predicted"); ax.set_ylabel("Actual"); ax.set_title(title)
    fig.tight_layout(); fig.savefig(path, dpi=150); plt.close(fig)
