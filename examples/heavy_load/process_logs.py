import argparse
from collections import defaultdict
import matplotlib.pyplot as plt
import numpy as np
import textwrap
from matplotlib.ticker import MaxNLocator

parser = argparse.ArgumentParser(
                    prog='ProcessLogs',
                    description='Process GCP logs')

parser.add_argument('--authorizer-logs', type=str, default="logs.txt", help='Location of cloud log file')
parser.add_argument('--rt-logs', type=str, default="laptop_rt_time_logs.txt", help='Location of local log file')
parser.add_argument('--plots-dir', type=str, default="plots", help='Directory to save plots')
parser.add_argument('--rt-only', action='store_true', help='Only process round trip logs')
args = parser.parse_args()

DELIMITER = "---"
PAYLOAD_KEY = "textPayload"
TIMESTAMP_KEY = "timestamp"

def process_logs(logs: str):
    times = {}
    with open(logs, 'r') as f:
        lines = f.readlines()
        for i in range(len(lines)):
            line = lines[i]
            if PAYLOAD_KEY not in line:
                continue
            if TIMESTAMP_KEY not in lines[i + 1]:
                if not ("GET" in line or "POST" in line or "CREATE_AUTH" in line):
                    continue
                if not ("<<" in line):
                    continue
                process_payload_simple(line.strip() + " " + lines[i + 1].strip(), times)
                i += 1
            else:
                if not ("GET" in line or "POST" in line or "CREATE_AUTH" in line):
                    continue
                if not ("<<" in line):
                    continue
                process_payload_simple(line.strip(), times)
    #print(times)

    get_times = defaultdict(list)
    post_times = defaultdict(list)
    create_auth_times = defaultdict(list)
    for key, time_breakdown in times.items():
        if "GET" in key:
            for k, v in time_breakdown.items():
                get_times[k].append(v)
        elif "POST" in key:
            for k, v in time_breakdown.items():
                post_times[k].append(v)
        elif "CREATE_AUTH" in key:
            for k, v in time_breakdown.items():
                create_auth_times[k].append(v)
        else:
            print("Unknown key", key)

    plot_times(get_times, "GET")
    plot_times(post_times, "POST")
    plot_times(create_auth_times, "CREATE_AUTH")

def plot_times(times: dict, name: str):
    print(f"------------------ {name} ------------------")
    for k, t_list in times.items():
        print(k, f"| Median: {np.median(np.array(t_list))} ms")
        plt.hist(t_list, bins=10, edgecolor='black')
        title = f"{name} {k}"
        wrapped_title = textwrap.fill(title, 60)  # Wrap after 60 characters
        plt.title(wrapped_title)

        # Use the formatter for the x-axis labels
        ax = plt.gca()
        # ax.xaxis.set_major_formatter(formatter)

        # Set the maximum number of x-axis labels to 10
        ax.xaxis.set_major_locator(MaxNLocator(nbins=10))

        plt.xlabel("Time (ms)")
        plt.savefig(f"{args.plots_dir}/{name}_{k}.png")
        plt.clf()

def process_end_payload(payload: str, time_dict: dict) -> str:
    payload = payload.split("textPayload: ")[1]
    time_for_this_step = payload.split(" -- ")[1]

    # Remove time
    payload = payload.split(" -- ")[0]
    request_id = payload.split(" ")[0]

    # Remove request ID
    payload = " ".join(payload.split(" ")[1:])

    # Get end condition
    end_condition = payload.split("|")[1].strip("]")

    parent = payload.split(" << ")[0]
    n_children = len(payload.split(" << ")[1:])
    if n_children == 0:
        if parent in time_dict:
            time_dict[parent][f"total ({end_condition})"] = time_for_this_step
        else:
            time_dict[parent] = {f"total ({end_condition})": time_for_this_step}
        return request_id
    if n_children == 1:
        first_child = payload.split(" << ")[1]
        if parent in time_dict:
            if first_child in time_dict[parent]:
                time_dict[parent][first_child][f"total ({end_condition})"] = time_for_this_step
            else:
                time_dict[parent][first_child] = {f"total ({end_condition})": time_for_this_step}
        return request_id
    

    return request_id 

def process_children(payload: str, time_dict: dict, time_for_this_step: float):
    if " << " not in payload:
        if payload in time_dict:
            time_dict[payload]["total"] = time_for_this_step
        else:
            time_dict[payload] = {"total": time_for_this_step}
        return
    parent = payload.split(" << ")[0]
    n_children = len(payload.split(" << ")[1:])
    first_child = payload.split(" << ")[1]
    if n_children == 1:
        if parent in time_dict:
            if first_child in time_dict[parent]:
                time_dict[parent][first_child]["total"] = time_for_this_step
            else:
                time_dict[parent][first_child] = {"total": time_for_this_step}
    
    payload = " << ".join(payload.split(" << ")[1:])
    if parent not in time_dict:
        time_dict[parent] = {}
    process_children(payload, time_dict[parent], time_for_this_step)

def process_payload(payload: str, time_dict: dict) -> str:
    """
    Process a payload and add the time to the time_dict.
    """
    payload = payload.split("textPayload: ")[1]
    time_for_this_step = payload.split(" -- ")[1]

    # Remove time
    payload = payload.split(" -- ")[0]
    request_id = payload.split(" ")[0]

    # Remove request ID
    payload = " ".join(payload.split(" ")[1:])

    process_children(payload, time_dict, float(time_for_this_step))

    return request_id

def process_payload_simple(payload: str, times: dict):
    payload = payload.split("textPayload: ")[1]
    time_for_this_step = float(payload.split(" -- ")[1]) * 1000

    # Remove time
    payload = payload.split(" -- ")[0]
    request_id = payload.split(" ")[0]

    # Remove request ID
    payload = " ".join(payload.split(" ")[1:])

    if request_id in times:
        times[request_id][payload] = time_for_this_step
    else:
        times[request_id] = {payload: time_for_this_step}
    
    return

def process_rt_logs(logs: str):
    task_to_index = {}
    index_to_start_time = {}
    create_vm_times = []
    get_image_times = []
    with open(logs, 'r') as f:
        lines = f.readlines()
        for i in range(len(lines)):
            line = lines[i].strip() 
            if "Time to get image" in line:
                # e.g., Time to get image 0:  7.785192251205444
                get_image_times.append(float(line.split(" ")[-1]))
            elif "Sending request" in line:
                # e.g., Sending request 1 of 1 to Sky Identity... (start time: 1711410758.185664)
                index = int(line.split(" ")[2])
                start_time = float(line.split(" ")[-1].strip(")"))
                index_to_start_time[index] = start_time
            elif "corresponds to" in line:
                # e.g., "Task-3 corresponds to index 1"
                index = int(line.split(" ")[-1])
                task = line.split(" ")[0]
                task_to_index[task] = index
            elif "End time" in line:
                # e.g., End time of Task-3 from callback: 1711410763.202663
                task = line.split(" ")[3]
                index = task_to_index[task]
                end_time = float(line.split(" ")[-1])
                create_vm_times.append(end_time - index_to_start_time[index])
            else:
                continue
    
    # Plot get image times  
    plt.hist(get_image_times, bins=10, edgecolor='black')
    title = f"Get image times: Round trip from laptop"
    wrapped_title = textwrap.fill(title, 60)  # Wrap after 60 characters
    plt.title(wrapped_title)

    # Use the formatter for the x-axis labels
    ax = plt.gca()

    # Set the maximum number of x-axis labels to 10
    ax.xaxis.set_major_locator(MaxNLocator(nbins=10))

    plt.xlabel("Time (s)")
    plt.savefig(f"{args.plots_dir}/round_trip_get_image.png")
    plt.clf()

        # Plot create vm times
    plt.hist(create_vm_times, bins=10, edgecolor='black')
    title = f"Create VM times: Round trip from laptop"
    wrapped_title = textwrap.fill(title, 60)  # Wrap after 60 characters
    plt.title(wrapped_title)

    # Use the formatter for the x-axis labels
    ax = plt.gca()

    # Set the maximum number of x-axis labels to 10
    ax.xaxis.set_major_locator(MaxNLocator(nbins=10))

    plt.xlabel("Time (s)")
    plt.savefig(f"{args.plots_dir}/round_trip_create_vm.png")
    plt.clf()

def main():
    if not (args.rt_only):
        process_logs(args.authorizer_logs)
    process_rt_logs(args.rt_logs)

if __name__ == "__main__":
    main()