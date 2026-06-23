import re
import logging

class BehaviourMonitor:
    """
    Parses behavioral logs collected from the guest VM.
    Currently supports parsing strace output for Linux guests.
    """
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def parse_strace(self, log_lines):
        """
        Parses strace log lines into a structured list of events.
        Example line: openat(AT_FDCWD, "/etc/passwd", O_RDONLY|O_CLOEXEC) = 3
        """
        events = []
        for line in log_lines:
            # File access events
            if 'openat' in line:
                match = re.search(r'openat\(.*?"(.*?)"', line)
                if match:
                    events.append({
                        "type": "file",
                        "action": "open",
                        "path": match.group(1),
                        "raw": line.strip(),
                        "syscall": "openat"
                    })

            # Process execution events
            elif 'execve' in line:
                match = re.search(r'execve\("(.*?)"', line)
                if match:
                    events.append({
                        "type": "process",
                        "action": "execute",
                        "path": match.group(1),
                        "raw": line.strip(),
                        "syscall": "execve"
                    })

            # Network connection events
            elif 'connect' in line:
                # Example: connect(3, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("1.2.3.4")}, 16)
                match = re.search(r'inet_addr\("(.*?)"\)', line)
                port_match = re.search(r'sin_port=htons\((\d+)\)', line)
                if match:
                    events.append({
                        "type": "network",
                        "action": "connect",
                        "dst_ip": match.group(1),
                        "dst_port": port_match.group(1) if port_match else "unknown",
                        "raw": line.strip(),
                        "syscall": "connect"
                    })

            # File deletion events
            elif 'unlink' in line:
                match = re.search(r'unlink\("(.*?)"', line)
                if match:
                    events.append({
                        "type": "file",
                        "action": "delete",
                        "path": match.group(1),
                        "raw": line.strip(),
                        "syscall": "unlink"
                    })
        return events

    def parse_procmon_csv(self, csv_lines):
        """
        Placeholder for parsing Windows Process Monitor (Procmon) CSV exports.
        """
        self.logger.warning("Procmon parsing is not yet implemented.")
        return []
