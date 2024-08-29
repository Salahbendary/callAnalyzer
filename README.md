# Call Analyzer Tool

## Overview

The Call Analyzer Tool is a Python-based application designed to analyze VoIP call data. It provides various functionalities such as visualizing packet distributions, detecting call start and end times, and analyzing traffic volume. The tool uses `tkinter` for the graphical user interface and supports various types of visualizations using `matplotlib`.

## Features

## Features

- **Upload Call Data**: Upload your VoIP call data in CSV format using the GUI.
  ![Upload Call Data](https://github.com/Salahbendary/callAnalyzer/blob/main/Images/callAnalyzerTool.png)

- **Packet Analysis**: Visualize TCP and UDP packet counts over time.
  ![Packet Analysis](https://github.com/Salahbendary/callAnalyzer/blob/main/Images/ProtocolDistribution.png)

- **Call Detection**: Detect call start and end times based on specific packet types.
  ![Call Detection](https://github.com/Salahbendary/callAnalyzer/blob/main/Images/PacketsDuringCall.png)

- **Traffic Volume Analysis**: Plot traffic volume over time and distribution of packet lengths.
  ![Traffic Volume Analysis](https://github.com/Salahbendary/callAnalyzer/blob/main/Images/TrafficOverTime.png)

- **Anomaly Detection**: Identify anomalies in packet lengths.
- **Geographic Information**: Retrieve and display geographic locations of source IPs using GeoLite2.

## Requirements

- Python 3.x
- pandas
- numpy
- matplotlib
- geoip2
- tkinter

