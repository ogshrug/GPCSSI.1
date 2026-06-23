class ThreatScorer:
    """
    Computes a heuristic threat score (0-100) based on analysis findings.
    """
    WEIGHTS = {
        "yara_match": 40,
        "suspicious_syscall": 20,
        "network_c2": 30,
        "file_persistence": 10
    }

    def compute(self, findings):
        """
        Calculates the threat score based on provided findings.
        :param findings: Dictionary containing 'yara_count', 'network_alerts',
                         'persistence_detected', and 'syscall_alerts'.
        """
        score = 0

        # Penalize for YARA matches
        if findings.get("yara_count", 0) > 0:
            score += self.WEIGHTS["yara_match"]
            # Additional penalty for multiple matches
            if findings.get("yara_count", 0) > 3:
                score += 10

        # Penalize for network activity indicative of C2
        if findings.get("network_alerts", 0) > 0:
            score += self.WEIGHTS["network_c2"]

        # Penalize for persistence mechanisms
        if findings.get("persistence_detected"):
            score += self.WEIGHTS["file_persistence"]

        # Penalize for suspicious system calls
        if findings.get("syscall_alerts", 0) > 0:
            score += min(self.WEIGHTS["suspicious_syscall"], findings["syscall_alerts"] * 5)

        return min(100, score)

    def get_verdict(self, score):
        """Returns a string verdict based on the numeric score."""
        if score < 30:
            return "clean"
        if score < 70:
            return "suspicious"
        return "malicious"
