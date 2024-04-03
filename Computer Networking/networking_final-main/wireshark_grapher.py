import pyshark
import pandas as pd
import os
import matplotlib.pyplot as plt

#  Convert pcap to csv
def recording_to_csv(filename, recording):
    if os.path.exists(filename):
        print("File already exists", filename)
        return
    pcap_file = recording
    capture = pyshark.FileCapture(pcap_file)

    packet_data = []
    for packet in capture:
        packet_info = {
            'timestamp': packet.sniff_time,
            'length': packet.length,
            'source_ip': packet.IPV6.src if hasattr(packet, 'IPV6') else None,
            'destination_ip': packet.IPV6.dst if hasattr(packet, 'IPV6') else None,
        }
        packet_data.append(packet_info)

    df = pd.DataFrame(packet_data)
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df.sort_values(by=['timestamp'], inplace=True)
    df['length'] = df['length'].astype(float)
    df.to_csv(filename, index=False)

# recording_to_csv('filtered_recording_1.csv', 'filtered_recording_1.pcapng')
recording_to_csv('filtered_recording_4.csv', 'recording_4.pcapng')
df = pd.read_csv('filtered_recording_4.csv')
df['timestamp'] = pd.to_datetime(df['timestamp'])
print(df.info())
print(df.head())

# Calculate the time difference between consecutive packets
df['time_diff'] = df['timestamp'] - df['timestamp'].shift(1)
df['time_diff'] = df['time_diff'].dt.seconds + df['time_diff'].dt.microseconds / 1000000
df['time_diff'] = df['time_diff'].fillna(0)
df.sort_values(by=['timestamp'], inplace=True)
print(df.head())
print(df['time_diff'].describe())

# parameters to make the new DataFrame
start_time = None
accumulated_length = 0
# Create lists to store the results
start_times = []
total_lengths = []

# Iterate through the DataFrame
for index, row in df.iterrows():
    if row['time_diff'] < 1:
        accumulated_length += row['length']
        if start_time is None:
            start_time = row['timestamp']
    else:
        if start_time is not None:
            start_times.append(start_time)
            total_lengths.append(accumulated_length)
        else:
            print('start_time is None *****')
        accumulated_length = 0
        start_time = None
result_df = pd.DataFrame({'start_time': start_times, 'total_length': total_lengths})
# Convert to MB
result_df['total_length'] = result_df['total_length'] / 1048576
# To make small values more visible (only for large differences in sizes between messages)
# result_df['total_length'] = result_df['total_length'] ** 0.5

print(result_df.head())
print(result_df.info())
print(result_df.describe())
print(result_df.shape)

plt.figure(figsize=(20, 10))
plt.bar(result_df['start_time'], result_df['total_length'], width=0.0001)

# Sizes of messages
plt.xlabel('Start Time')
plt.ylabel('MB')
plt.title('Total Length and Start Time')
plt.show()

# Create the PDF
plt.hist(df['time_diff'], bins=50, log=True)
plt.xlabel('Seconds')
plt.ylabel('Frequency')
plt.title('PDF of inter-messages delay')
plt.show()

# Create the CDF data
sorted_sizes = result_df['total_length'].sort_values()

# Calculate cumulative probabilities based on the rank of each value
sorted_sizes = sorted_sizes / sorted_sizes.max()
cumulative_prob = (sorted_sizes.rank() - 1) / len(sorted_sizes)
cumulative_prob = 1 - cumulative_prob

# Create a CDF plot
plt.plot(sorted_sizes, cumulative_prob, marker='.', linestyle='-')
plt.yscale('log')  # Use a logarithmic scale for the y-axis like the paper
plt.xlabel('Size')
plt.ylabel('Cumulative Probability')
plt.title('Cumulative Distribution Function (CDF) of Sizes')
plt.tight_layout()
plt.show()
