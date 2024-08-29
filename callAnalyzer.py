import tkinter as tk
from tkinter import filedialog
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import geoip2.database

# Create the main window
root = tk.Tk()
root.title("Call Analyzer Tool")
root.geometry("500x150")

# Add the message to the GUI
label = tk.Label(root, text="Analyzer Tool created by Salah Bendary\n\nKindly upload your Call to start analyzing it:")
label.pack(pady=20)

# Function to upload file
def upload_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        analyze_call(file_path)

# Add a button to upload file
button = tk.Button(root, text="Upload Call File", command=upload_file)
button.pack(pady=10)

# Function to analyze the call data
def analyze_call(file_path):
    # Load the data
    data = pd.read_csv(file_path, sep=",", encoding="ISO-8859-1")

    # Inspect the first few rows of the data
    print(data.head())

    listOfTimeStamps = data['Time'].values
    listOfProtocols = data['Protocol'].values
    listOfInfos = data['Info'].values

    TCPpackets = list(map(lambda p: 1 if "TCP" in p else 0, listOfProtocols))
    UDPpackets = list(map(lambda p: 1 if "UDP" in p or "STUN" in p or "DNS" in p else 0, listOfProtocols))

    def detectWhenCallsEnded():
        timestamps = []
        unknownRequestInfoPackets = list(map(lambda i: 1 if "Unknown Request" in i else 0, listOfInfos))
        count = 0
        for i in range(len(unknownRequestInfoPackets)):
            if unknownRequestInfoPackets[i] == 1 and listOfProtocols[i] == "STUN":
                count += 1
                if count == 5:
                    timestamps.append(listOfTimeStamps[i-4])
            else:
                count = 0
        return timestamps

    def detectWhenCallsAnswered():
        timestamps = []
        successRequestInfoPackets = list(map(lambda i: 1 if "Allocate Success Response" in i else 0, listOfInfos))
        count = 0
        for i in range(len(successRequestInfoPackets)):
            if successRequestInfoPackets[i] == 1 and listOfProtocols[i] == "STUN":
                count += 1
                if count == 10 and listOfProtocols[i+1] == "UDP":
                    timestamps.append(listOfTimeStamps[i-4])
            else:
                count = 0
        return timestamps

    startOfCallTimeStamps = detectWhenCallsAnswered()
    endOfCallTimeStamps = detectWhenCallsEnded()

    for i in range(len(startOfCallTimeStamps)):
        print(f"A call started after {startOfCallTimeStamps[i]:.2f} seconds and lasted for {endOfCallTimeStamps[i] - startOfCallTimeStamps[i]:.2f} seconds")

    def countNumberOfPackets(packets, timestamps, cap):
        returnedPackets = []
        returnedtimestamps = []
        count = 0
        time = 0
        timePrev = 0
        for i in range(timestamps.size):
            time = float(timestamps[i])
            protocol = packets[i]
            if (time - timePrev) >= 0.1:
                if count > cap:
                    count = cap
                returnedPackets.append(count)
                returnedtimestamps.append(time)
                count = 0
            if protocol:
                count += 1
            timePrev = time
        returnedPackets.append(count)
        returnedtimestamps.append(time)
        return returnedPackets, returnedtimestamps

    TCPpackets, timestamps = countNumberOfPackets(TCPpackets, listOfTimeStamps, 200)
    UDPpackets, timestamps = countNumberOfPackets(UDPpackets, listOfTimeStamps, max(TCPpackets) + 40)

    plt.figure(figsize=(12, 6))
    plt.plot(timestamps, TCPpackets, color="blue", label="TCP")
    plt.plot(timestamps, UDPpackets, color="pink", label="UDP")

    for t in startOfCallTimeStamps:
        plt.plot(t, 0, 'go')
        plt.axvline(t, 0, 100, label='Start Of Call', color="green", linewidth=2)

    for t in endOfCallTimeStamps:
        plt.plot(t, 0, 'ro')
        plt.axvline(t, 0, 100, label='End Of Call', color="red", linewidth=2)

    plt.ylabel('Number of packets')
    plt.xlabel('Time in seconds')
    plt.legend(loc="upper left")
    plt.title('Packets recorded during a VoIP call')
    plt.margins(0, 0.05, tight=True)
    plt.xticks(np.arange(0, int(timestamps[-1]), 5))
    plt.ylim(bottom=0)
    
    top_sources = data['Source'].value_counts().head(10)
    top_destinations = data['Destination'].value_counts().head(10)

    plt.figure(figsize=(12, 6))

    plt.subplot(1, 2, 1)
    top_sources.plot(kind='bar', color='blue')
    plt.title('Top 10 Source IPs')

    plt.subplot(1, 2, 2)
    top_destinations.plot(kind='bar', color='orange')
    plt.title('Top 10 Destination IPs')

    plt.tight_layout()
    
    plt.figure(figsize=(8, 6))
    plt.hist(data['Length'], bins=50, color='purple', edgecolor='black')
    plt.title('Packet Length Distribution')
    plt.xlabel('Length (bytes)')
    plt.ylabel('Frequency')

    data['Time'] = data['Time'].astype(float)
    traffic_volume = data.groupby(data['Time'].astype(int))['Length'].sum()

    plt.figure(figsize=(12, 6))
    plt.plot(traffic_volume.index, traffic_volume.values, color='teal')
    plt.title('Traffic Volume Over Time')
    plt.xlabel('Time (seconds)')
    plt.ylabel('Total Length (bytes)')
    
    conversation_groups = data.groupby(['Source', 'Destination'])
    conversation_stats = conversation_groups.agg({
        'Length': ['sum', 'count'],
        'Time': ['min', 'max']
    })
    conversation_stats.columns = ['TotalLength', 'PacketCount', 'StartTime', 'EndTime']
    conversation_stats['Duration'] = conversation_stats['EndTime'] - conversation_stats['StartTime']

    conversation_stats_sorted = conversation_stats.sort_values(by='TotalLength', ascending=False).head(10)
    print(conversation_stats_sorted)

    tcp_data = data[data['Protocol'] == 'TCP']
    udp_data = data[data['Protocol'] == 'UDP']

    plt.figure(figsize=(12, 6))

    plt.subplot(1, 2, 1)
    plt.hist(tcp_data['Length'], bins=50, color='blue', edgecolor='black')
    plt.title('TCP Packet Length Distribution')

    plt.subplot(1, 2, 2)
    plt.hist(udp_data['Length'], bins=50, color='green', edgecolor='black')
    plt.title('UDP Packet Length Distribution')

    plt.tight_layout()

    mean_length = data['Length'].mean()
    std_length = data['Length'].std()
    anomaly_threshold = mean_length + 3 * std_length

    anomalies = data[data['Length'] > anomaly_threshold]
    print(f"Detected {len(anomalies)} anomalies.")
    print(anomalies)

    from pandas.plotting import autocorrelation_plot

    plt.figure(figsize=(8, 6))
    autocorrelation_plot(traffic_volume)
    plt.title('Autocorrelation of Traffic Volume')

    # Load GeoLite2 database
    reader = geoip2.database.Reader('GeoLite2-City.mmdb')

    def get_location(ip):
        try:
            response = reader.city(ip)
            return response.country.name, response.city.name
        except:
            return None, None

    data['Country'], data['City'] = zip(*data['Source'].apply(get_location))

    print(data[['Source', 'Country', 'City']].dropna().head(10))

    # Display all figures together
    plt.show()

    # Keep the terminal open after execution
    input("Press Enter to exit...")

# Run the GUI loop
root.mainloop()
