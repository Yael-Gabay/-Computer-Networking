import sys
import threading
from scapy.all import sr1
from scapy.layers.inet import *
from watchdog import start_watchdog

if len(sys.argv) != 2:
    print("python3 ping.py <IP>")
    exit()
else:
    ip = sys.argv[1]

watchdog = start_watchdog(ip)


def send_ping():
    global watchdog
    while True:
        start = time.time()
        request = IP(dst=ip) / ICMP()  # Create ICMP packet

        response = sr1(request, timeout=12, verbose=0)  # Send ICMP packet and wait for response
        # the timeout is larger than the watchdog timer so the watchdog will be the one to terminate the program
        end = time.time()

        # Manual check, is it really more than 10 seconds he exits the program
        # if ip == '8.8.8.8':
        #     time.sleep(12)

        # Check if the response took more than 10 seconds
        if end - start > 10:
            watchdog.stop()  # Stop the watchdog
            exit()

        print('Reply from ' + ip + ': bytes=' + str(len(response)) + ' time=' + str(round((end - start) * 1000)) + 'ms')

        watchdog.reset_timer()  # Reset the watchdog timer
        time.sleep(1)  # Wait for 1 second


def stop_watchdog():
    global watchdog
    watchdog.stop()


try:
    # Start the ping thread
    ping_thread = threading.Thread(target=send_ping)
    ping_thread.start()

    # Wait for the ping thread to complete
    ping_thread.join()

except KeyboardInterrupt:
    print("\nExiting...")
    stop_watchdog()
    exit()
