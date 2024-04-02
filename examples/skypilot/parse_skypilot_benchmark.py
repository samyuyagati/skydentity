from datetime import datetime
import matplotlib.pyplot as plt
import numpy as np
import os

def parse_std_err(fname):
   with open(fname, "r") as f:
        lines = f.readlines() 
        for line in lines:
            if "real" in line:
                return float(line.split()[0])

def parse_std_out(fname):
    with open(fname, "r") as f:
        lines = f.readlines()
        for line in lines:
            if "Creating a new cluster" in line:
                start_time_str = line.split(" ")[2]
                start_time = datetime.strptime(start_time_str, '%H:%M:%S')
            if "Head node is up" in line:
                end_time_str = line.split(" ")[2]
                end_time = datetime.strptime(end_time_str, '%H:%M:%S')
        total_time_seconds = float((end_time - start_time).total_seconds())
        return total_time_seconds

def plot(provision_times, times_to_head_node_up, dirname):
    # Create stacked bar plot
    labels = [f"{i}" for i in range(len(provision_times))]
    x = np.arange(len(provision_times))  # the label locations
    width = 0.35  # the width of the bars

    fig, ax = plt.subplots(figsize=(10, 4))
    ax.bar(x, times_to_head_node_up, width, label='Time to start VM')
    ax.bar(x, [provision_times[i] - times_to_head_node_up[i] for i in range(len(provision_times))], width, bottom=times_to_head_node_up, label="Add'l time to provision")

    ax.set_ylabel('Times')
    ax.set_xlabel('sky-launch call index (0-39)')
    ax.set_title(f'Time to provision for sky launch ({dirname})')
    ax.set_xticks(x[::5])  # Select every 5th label
    ax.set_xticklabels(labels[::5])  # Select every 5th label
    #ax.set_xticks(x)
    #ax.set_xticklabels(labels)
    ax.legend()

    plt.savefig(f"skypilot_{dirname}.png")
    plt.show()

def process_dir(dirname):
    files = os.listdir(dirname)
    provision_times = []
    times_to_head_node_up = []
    for filename in files:
        if "stderr" in filename:
            provision_times.append(parse_std_err(os.path.join(dirname, filename)))
        if "stdout" in filename:
            times_to_head_node_up.append(parse_std_out(os.path.join(dirname, filename)))
    print(f"{dirname}: {np.mean(np.array(provision_times))} s to provision (avg), {np.mean(np.array(times_to_head_node_up))} s to head node up (avg)")
    plot(provision_times, times_to_head_node_up, dirname)

def main():
    process_dir("batch_10_skydentity")
    process_dir("batch_10_baseline") 
    process_dir("sequential_skydentity")
    process_dir("sequential_baseline")   

if __name__ == '__main__':
    main()