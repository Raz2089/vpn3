import threading
import socket
import struct
import pydivert
from collections import deque
import tkinter as tk
from datetime import datetime

SERVER_ADDRESS = "10.100.102.8"
SERVER_PORT = 3030

server_sock = socket.socket()
server_sock.bind((SERVER_ADDRESS, SERVER_PORT))
server_sock.listen()
print("connected to server")

connection_map = {}
map_lock = threading.Lock()

packets_to_send_to_web = deque()
packets_to_web_lock = threading.Lock()

# GUI variables
connected_clients = {}  # {addr: {'connect_time': datetime, 'frame': widget, 'socket': client_sock}}
root = None


def recv_all(sock, n):
    data = b''
    while len(data) < n:
        part = sock.recv(n - len(data))
        if not part:
            break
        data += part
    return data


def add_to_connection_map(packet, client_sock, client_ip, client_port, interface):
    key = (packet.dst_addr, packet.dst_port)
    with map_lock:
        if key not in connection_map:
            connection_map[key] = (client_sock, client_ip, int(client_port), interface)


def handle_client(client_sock, addr):
    try:
        while True:
            try:
                metadata_len = struct.unpack("!I", recv_all(client_sock, 4))[0]
                if metadata_len == 0:  # Connection closed
                    break

                meta_data = recv_all(client_sock, metadata_len).decode()
                if not meta_data:  # Connection closed
                    break

                client_ip, client_port, interface_id = meta_data.strip().split(":")
                interface = tuple(map(int, interface_id.strip("()").split(",")))

                raw_packet_len = struct.unpack("!I", recv_all(client_sock, 4))[0]
                if raw_packet_len == 0:  # Connection closed
                    break

                packet_raw = recv_all(client_sock, raw_packet_len)
                if not packet_raw:  # Connection closed
                    break

                packet = pydivert.Packet(raw=packet_raw, direction=pydivert.Direction.OUTBOUND, interface=interface)
                add_to_connection_map(packet, client_sock, client_ip, client_port, interface)
                with packets_to_web_lock:
                    packets_to_send_to_web.append(packet)
            except (ConnectionResetError, ConnectionAbortedError, OSError):
                # Socket was closed
                break
            except Exception as e:
                print(f"Error handling client {addr}: {e}")
                break
    finally:
        # Clean up when client disconnects
        disconnect_client(addr)
        try:
            client_sock.close()
        except:
            pass


def send_packets_to_web():
    with pydivert.WinDivert("false") as w:
        while True:
            with packets_to_web_lock:
                if packets_to_send_to_web:
                    packet = packets_to_send_to_web.popleft()
                    w.send(packet)
                    print("packet sent to web")


def sniff_responses_from_web():
    filter_str = f"inbound and ip and (tcp or udp)"
    with pydivert.WinDivert(filter_str) as w:
        while True:
            packet_from_web = w.recv()
            key = (packet_from_web.src_addr, packet_from_web.src_port)
            with map_lock:
                entry = connection_map.get(key)
                if entry:
                    print("recieved packet from web", packet_from_web)
                    client_sock, client_ip, client_port, interface_id = entry
                    packet_from_web.interface = interface_id
                    packet_from_web.dst_addr = client_ip
                    packet_from_web.dst_port = client_port
                    packet_from_web.recalculate_checksums()
                    print("sending back to the client")
                    try:
                        client_sock.sendall(
                            struct.pack("!I", len(bytes(packet_from_web.raw))) + bytes(packet_from_web.raw))
                    except:
                        # Client socket is closed, remove from connection map
                        del connection_map[key]
                else:
                    w.send(packet_from_web)


def create_client_square(addr, client_sock):
    """Create a square widget for a connected client"""
    if root is None:
        return

    ip, port = addr

    # Create frame for client
    client_frame = tk.Frame(root, bg='#404040', relief='raised', bd=2, width=200, height=150)
    client_frame.pack_propagate(False)
    client_frame.pack(side='left', padx=10, pady=10)

    # Client icon (simple rectangle representing user)
    icon_frame = tk.Frame(client_frame, bg='#606060', width=60, height=60)
    icon_frame.pack_propagate(False)
    icon_frame.pack(pady=10)

    # Add simple "user" text in icon
    tk.Label(icon_frame, text="👤", font=('Arial', 20), bg='#606060', fg='white').pack(expand=True)

    # Client IP
    tk.Label(client_frame, text=f"IP: {ip}", font=('Arial', 10), bg='#404040', fg='white').pack()

    # Client Port
    tk.Label(client_frame, text=f"Port: {port}", font=('Arial', 10), bg='#404040', fg='white').pack()

    # Connection time label (will be updated)
    time_label = tk.Label(client_frame, text="Connected: 0s", font=('Arial', 9), bg='#404040', fg='lightgreen')
    time_label.pack()

    # Click to disconnect
    def disconnect_click():
        force_disconnect_client(addr)

    client_frame.bind("<Button-1>", lambda e: disconnect_click())
    for child in client_frame.winfo_children():
        child.bind("<Button-1>", lambda e: disconnect_click())

    # Store client info including the socket
    connected_clients[addr] = {
        'connect_time': datetime.now(),
        'frame': client_frame,
        'time_label': time_label,
        'socket': client_sock
    }


def force_disconnect_client(addr):
    """Forcefully disconnect a client by closing its socket"""
    if addr in connected_clients:
        print(f"Force disconnecting client {addr}")

        # Close the socket first
        try:
            client_sock = connected_clients[addr]['socket']
            client_sock.close()
            print(f"Socket closed for {addr}")
        except Exception as e:
            print(f"Error closing socket for {addr}: {e}")

        # The handle_client thread will detect the closed socket and call disconnect_client()


def disconnect_client(addr):
    """Remove client from GUI and connections (called when client naturally disconnects)"""
    if addr in connected_clients:
        # Remove from GUI
        try:
            connected_clients[addr]['frame'].destroy()
        except:
            pass
        del connected_clients[addr]
        print(f"Client {addr} disconnected")

        # Remove from connection map
        with map_lock:
            keys_to_remove = []
            for key, value in connection_map.items():
                if value[1] == addr[0] and value[2] == addr[1]:
                    keys_to_remove.append(key)
            for key in keys_to_remove:
                del connection_map[key]


def update_client_times():
    """Update connection time for each client"""
    for addr, client_info in list(connected_clients.items()):  # Use list() to avoid dict changed during iteration
        try:
            elapsed = datetime.now() - client_info['connect_time']
            seconds = int(elapsed.total_seconds())

            if seconds < 60:
                time_text = f"Connected: {seconds}s"
            elif seconds < 3600:
                minutes = seconds // 60
                time_text = f"Connected: {minutes}m"
            else:
                hours = seconds // 3600
                minutes = (seconds % 3600) // 60
                time_text = f"Connected: {hours}h {minutes}m"

            client_info['time_label'].config(text=time_text)
        except:
            # Client might have been disconnected
            pass

    # Schedule next update
    if root:
        root.after(1000, update_client_times)


def create_gui():
    """Create the simple GUI"""
    global root
    root = tk.Tk()
    root.title("VPN Clients")
    root.configure(bg='#2c2c2c')
    root.geometry("600x600")

    # Title
    tk.Label(root, text="Connected VPN Clients (Click to Disconnect)",
             font=('Arial', 14, 'bold'), bg='#2c2c2c', fg='white').pack(pady=10)

    # Start updating times
    update_client_times()

    root.mainloop()


def server_main():
    """Main server function"""
    # Start server threads
    threading.Thread(target=send_packets_to_web, daemon=True).start()
    threading.Thread(target=sniff_responses_from_web, daemon=True).start()

    # Accept clients
    while True:
        try:
            client_conn, addr = server_sock.accept()
            print("Client connected:", addr)

            # Add to GUI - pass the socket too
            if root:
                root.after(0, lambda a=addr, s=client_conn: create_client_square(a, s))

            # Handle client
            threading.Thread(target=handle_client, args=(client_conn, addr), daemon=True).start()
        except:
            break


if __name__ == "__main__":
    # Start server in background thread
    threading.Thread(target=server_main, daemon=True).start()

    # Start GUI (this will block)
    create_gui()