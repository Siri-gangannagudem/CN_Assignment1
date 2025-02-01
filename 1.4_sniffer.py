import numpy as np

pps_values = []
mbps_values = []

with open("packet_sniffer.txt", "r") as file:
    for line in file:
        if "Packets Per Second (pps):" in line:
            pps_values.append(float(line.split(":")[1].strip()))
        elif "Megabits Per Second (mbps):" in line:
            mbps_values.append(float(line.split(":")[1].strip()))

pps_values = np.array(pps_values)
mbps_values = np.array(mbps_values)

print("### Packet Rate (PPS) ###")
print(f"Average PPS: {np.mean(pps_values):.6f}")
print(f"Max PPS: {np.max(pps_values):.6f}")
print(f"Min PPS: {np.min(pps_values):.6f}")

print("\n### Bandwidth (Mbps) ###")
print(f"Average Mbps: {np.mean(mbps_values):.6f}")
print(f"Max Mbps: {np.max(mbps_values):.6f}")
print(f"Min Mbps: {np.min(mbps_values):.6f}")
