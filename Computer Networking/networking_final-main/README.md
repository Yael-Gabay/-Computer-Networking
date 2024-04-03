# Packet Recording Analysis

This Python script is designed to analyze recordings of encrypted packets from network captures saved in PCAP format. The script will form a dataframe representing secure instant messages sizes and time of transmission. The script will then plot the data in a bar graph. It will also show the PDF of inter-packet delays and the CDF of message sizes.

## Requirements

- Python 3 or higher (tested on Python 3.9)
- `pyshark` library
- `pandas` library
- `matplotlib` library
- `os` library

Install the required libraries using the following command:

```bash
pip install pyshark pandas matplotlib
```
Get examples of traffic recordings in the resources directory via the Google Drive link.

## Usage
Simply replace the path in the arguments for recording_to_csv() with the path your own PCAP file and desired csv path and run the script. The script will output a bar graph of the data.

After running the script for the first time, a csv file will be created in the specified path. The script will use this csv file for future runs to save time. 

## Output
The script will output a bar graph of the data. The x-axis represents the time of transmission and the y-axis represents the size of the message in MBs.

***Here is an example of the output:***
![graph_2](https://github.com/GiladFisher/networking_final/assets/97436308/83ecb145-412f-4802-ade8-0b3a0fb8c445)

***PDF:***
![PDF_2](https://github.com/GiladFisher/networking_final/assets/97436308/ef12bbfd-7847-49fb-a667-35dfd27b13b4)

***CDF:***
![CDF_2](https://github.com/GiladFisher/networking_final/assets/97436308/3e6a1959-2347-4146-aa6c-86d0e4bdd0c4)


**Each folder has a summary of main results and an explanation of what we did.

***we used ChatGPT in this project***
