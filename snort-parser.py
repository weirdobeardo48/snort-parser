import time
import re
import subprocess


def follow(thefile):
    thefile.seek(0, 2)
    current_log = ""
    while True:
        # print("Seeking")
        line = thefile.readline()
        if not line:
            time.sleep(0.2)
            continue
        yield line


def check_existed_rule(ip):
    bash_command = "iptables-save | grep %s " % ip
    process = subprocess.Popen(bash_command.split(), stdout=subprocess.PIPE, shell=True)
    while process.poll() is None:
        line = process.stdout.readline()
        line = line.decode("utf-8").strip()
        if ip in line:
            print("%s is already blocked from pinging our fucking server" % ip)
            return True
    return False


if __name__ == '__main__':
    logfile = open("/var/log/snort/alert", "r")
    loglines = follow(logfile)
    for line in loglines:
        ahihi = re.search("\\d+.\\d+.\\d+.\\d+\\s+(->|<>)\\s+\\d+.\\d+.\\d+\\d.+", line)
        if ahihi:
            ips = re.split("\\s+(->|<>)\\s+", ahihi.group(0).strip())
            print("Length of IPS: %s" % (str(len(ips))))
            if len(ips) == 3:
                # print(ips[0])
                # print(ips[2])
                if not check_existed_rule(str(ips[0])):
                    iptables_rule = "iptables -I INPUT -p icmp -s %s -m comment --comment \"Auto-Drop-ICMP-Via-Snort-By-TruongNX\" -j DROP" % (
                        str(ips[0]))
                    process = subprocess.run(iptables_rule.split(), stdout=subprocess.PIPE)
                    print("IP %s has been block from pinging our fucking server" % str(ips[0]))

# Drop rule
# iptables-save | grep -v Auto-Drop-ICMP-Via-Snort-By-TruongNX | iptables-restore
