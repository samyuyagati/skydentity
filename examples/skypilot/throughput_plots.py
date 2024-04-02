import matplotlib.pyplot as plt
import numpy as np

def process_batch_times(fname):
    with open(fname, "r") as f:
        lines = f.readlines()
        times = []
        total = 0
        for line in lines:
            if "BATCH TIME (s):" in line:
                times.append(10.0/float(line.split()[-1]))
            if "TOTAL TIME (s):" in line:
                total = 40.0/float(line.split()[-1])
        return (times, total)

def plot_batch_times(baseline_fname, skydentity_fname, batch_size=10):
    baseline_times, baseline_total = process_batch_times(baseline_fname)
    baseline_times.append(baseline_total)
    skydentity_times, skydentity_total = process_batch_times(skydentity_fname)
    skydentity_times.append(skydentity_total)
    x = np.arange(len(baseline_times)) + 2
    width = 0.35
    fig, ax = plt.subplots(figsize=(10, 4))
    ax.bar(x, baseline_times, width, label='Baseline')
    ax.bar(x + width, skydentity_times, width, label='w/ Skydentity')
    ax.set_ylabel('Req/s')
    ax.set_title(f"Throughput (Batch size {batch_size})")
    ax.set_xticks(x)
    x_labels = [f"Batch {i}" for i in range(len(baseline_times))]
    x_labels[-1] = "Total"
    ax.set_xticklabels(x_labels)
    ax.legend()
    plt.savefig(f"batch_times_{batch_size}.png")
    plt.show()

def main():
    plot_batch_times("batch_10_baseline/batch_times.txt", "batch_10_skydentity/batch_times.txt")

if __name__ == "__main__":
    main()