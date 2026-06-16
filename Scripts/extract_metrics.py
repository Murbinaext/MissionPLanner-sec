import clr
import System
from System import DateTime, TimeSpan, Action, IObserver, Int32
from System.Threading import Thread

class MAVLinkObserver(IObserver[Int32]):
    def __init__(self, callback):
        # Store the callback function to execute
        self.callback = callback
        
    def OnNext(self, value):
        # Execute the callback when data is received
        self.callback(value)
        
    def OnError(self, error):
        # Network errors are ignored in this context
        pass
        
    def OnCompleted(self):
        # No action required upon completion
        pass

clr.AddReference("MissionPlanner")
import MissionPlanner

csv_path = r"C:\Users\devel\Desktop\metricas_cripto.csv"
interval_ms = 1000

port = MissionPlanner.MainV2.comPort
if port is None or port.MAV is None:
    raise Exception("No active connection found on MainV2.comPort")

total_bytes_rx = 0
total_bytes_tx = 0
total_packets_rx = 0
total_packets_lost = 0
packet_receive_events = []
packet_lost_events = []
bytes_received_events = []
bytes_sent_events = []
last_packet_receive_time = None
max_packet_interval_ms = 0

def prune_events(events, window_ms):
    cutoff = DateTime.UtcNow.AddMilliseconds(-window_ms)
    while events and events[0][0] < cutoff:
        events.pop(0)

def sum_event_counts(events):
    return sum(count for _, count in events)

def on_bytes_received(count):
    global total_bytes_rx
    value = int(count)
    total_bytes_rx += value
    bytes_received_events.append((DateTime.UtcNow, value))

def on_bytes_sent(count):
    global total_bytes_tx
    value = int(count)
    total_bytes_tx += value
    bytes_sent_events.append((DateTime.UtcNow, value))

def on_packet_received(count):
    global total_packets_rx, last_packet_receive_time, max_packet_interval_ms
    now = DateTime.UtcNow
    value = int(count)
    total_packets_rx += value
    packet_receive_events.append((now, value))

    if last_packet_receive_time is not None:
        interval = now - last_packet_receive_time
        interval_ms_value = int(interval.TotalMilliseconds)
        if interval_ms_value > max_packet_interval_ms:
            max_packet_interval_ms = interval_ms_value

    last_packet_receive_time = now

def on_packet_lost(count):
    global total_packets_lost
    value = int(count)
    total_packets_lost += value
    packet_lost_events.append((DateTime.UtcNow, value))

# Subscribe by injecting the bridge class to comply with C# IObserver interface
subscriptions = [
    port.BytesReceived.Subscribe(MAVLinkObserver(on_bytes_received)),
    port.BytesSent.Subscribe(MAVLinkObserver(on_bytes_sent)),
    port.WhenPacketReceived.Subscribe(MAVLinkObserver(on_packet_received)),
    port.WhenPacketLost.Subscribe(MAVLinkObserver(on_packet_lost))
]

with open(csv_path, "w") as f:
    f.write("Timestamp,BytesRx,BytesTx,PacketsRx,PacketsLost,PacketsPerSecond,LinkQualityPercent,MaxPacketIntervalMs\n")

print("Recording metrics. To stop, abort the script in Mission Planner.")

try:
    while True:
        try:
            if port is None or port.MAV is None:
                Script.Sleep(interval_ms)
                continue

            prune_events(packet_receive_events, 3000)
            prune_events(packet_lost_events, 3000)
            prune_events(bytes_received_events, 3000)
            prune_events(bytes_sent_events, 3000)

            received_last_3s = sum_event_counts(packet_receive_events)
            lost_last_3s = sum_event_counts(packet_lost_events)
            packets_per_second = received_last_3s / 3.0

            quality = 0
            if received_last_3s + lost_last_3s > 0:
                quality = int(round(received_last_3s / float(received_last_3s + lost_last_3s) * 100.0))

            timestamp = DateTime.Now.ToString("HH:mm:ss.fff")

            line = "{},{},{},{},{},{:.2f},{},{}\n".format(
                timestamp,
                total_bytes_rx,
                total_bytes_tx,
                total_packets_rx,
                total_packets_lost,
                packets_per_second,
                quality,
                max_packet_interval_ms
            )

            with open(csv_path, "a") as f:
                f.write(line)

            Script.Sleep(interval_ms)

        except SystemError:
            raise

        except Exception as e:
            print("Warning: " + str(e))
            Script.Sleep(interval_ms)

except SystemError:
    # 1. Notify via console
    print("Script cleanly terminated by the user.")
    
    # 2. Cancel the .NET ThreadAbortException to prevent zombie errors
    try:
        Thread.ResetAbort()
    except:
        pass

finally:
    # 3. Safely clean up memory and dispose subscriptions
    for sub in subscriptions:
        try:
            sub.Dispose()
        except:
            pass
    print("Subscriptions released. Shutdown complete.")
