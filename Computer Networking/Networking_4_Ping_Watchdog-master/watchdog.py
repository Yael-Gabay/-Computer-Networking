import socket
import threading
import time

class Watchdog(threading.Thread):
    def __init__(self, ip):
        super().__init__()
        self.ip = ip
        self.timer = 0
        self.lock = threading.Lock()
        self.stop_event = threading.Event()

    def run(self):
        while not self.stop_event.is_set():
            with self.lock:
                if self.timer >= 10:
                    print("Server {} cannot be reached.".format(self.ip))
                    # Perform any necessary actions when the server is unreachable
                    break

            time.sleep(1)  # Sleep for 1 second
            with self.lock:
                self.timer += 1

    def reset_timer(self):
        with self.lock:
            self.timer = 0

    def stop(self):
        self.stop_event.set()


def start_watchdog(ip):
    watchdog = Watchdog(ip)
    watchdog.start()
    return watchdog
