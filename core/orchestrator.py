import logging
import asyncio
import os
from datetime import datetime
from core.vm_manager import VMManager
from core.yara_engine import YaraEngine
from core.behaviour_monitor import BehaviourMonitor
from core.threat_scorer import ThreatScorer
import hashlib

class Orchestrator:
    """
    Coordinates the entire malware analysis process.
    This includes static analysis (YARA), VM orchestration, behavior monitoring,
    and threat scoring.
    """
    def __init__(self, db, vm_manager=None, ui_callback=None):
        """
        Initializes the Orchestrator.
        :param db: Database instance for logging results.
        :param vm_manager: VMManager instance for virtual machine control.
        :param ui_callback: Optional callable for reporting progress to the UI.
        """
        self.db = db
        self.vm_manager = vm_manager or VMManager()
        self.logger = logging.getLogger(__name__)
        self.ui_callback = ui_callback
        self.yara_engine = YaraEngine()
        self.behaviour_monitor = BehaviourMonitor()
        self.threat_scorer = ThreatScorer()

    def _notify_ui(self, message, severity="INFO"):
        """Sends updates back to the UI if a callback is provided."""
        if self.ui_callback:
            self.ui_callback(message, severity)

    async def run_analysis(self, sample_path, guest_os="ubuntu-clean", snapshot_name="clean-baseline", run_gui=False):
        """
        Runs a full analysis on a given malware sample.
        """
        self.logger.info(f"Starting analysis for {sample_path} on {guest_os} (Snapshot: {snapshot_name}, GUI: {run_gui})")
        self._notify_ui(f"Starting analysis on {guest_os} (Snapshot: {snapshot_name})...")

        # 0. Static Analysis (YARA)
        self._notify_ui("Running YARA static analysis...")
        matches = await self.yara_engine.scan_file_async(sample_path)
        for match in matches:
            self._notify_ui(f"YARA Match: {match}", "WARN")

        # 1. Prepare Sample metadata and Database entry
        try:
            with open(sample_path, "rb") as f:
                data = f.read()
                sha256 = hashlib.sha256(data).hexdigest()
                md5 = hashlib.md5(data).hexdigest()

            sample_id = await self.db.add_sample(sha256, md5, os.path.basename(sample_path), "unknown", len(data))
            analysis_id = await self.db.create_analysis(sample_id, datetime.now())
        except Exception as e:
            self.logger.error(f"Failed to initialize analysis in DB: {e}")
            self._notify_ui(f"Failed to initialize analysis: {e}", "CRITICAL")
            return None

        try:
            # 2. Verify and Reset VM Environment
            self._notify_ui("Verifying VM environment...")
            ok, msg = await self.vm_manager.verify_environment(guest_os)
            if not ok:
                raise RuntimeError(msg)

            self._notify_ui(f"Reverting VM to snapshot {snapshot_name}...")
            await self.vm_manager.revert_to_snapshot(guest_os, snapshot_name=snapshot_name)

            self._notify_ui("Injecting sample into VM...")
            guest_sample_path = "/malware_sample"
            if not await self.vm_manager.inject_file(guest_os, sample_path, guest_sample_path):
                raise RuntimeError("Failed to inject sample into guest VM.")

            self._notify_ui("Starting VM and waiting for guest agent...")
            if not await self.vm_manager.start_vm(guest_os):
                raise RuntimeError("Failed to start VM.")

            # Wait for guest agent to respond before running commands
            if not await self.vm_manager.wait_for_guest_agent(guest_os):
                raise RuntimeError("Guest agent timed out.")

            if run_gui:
                self._notify_ui("Opening VM GUI...")
                await self.vm_manager.open_gui(guest_os)

            # 4. Execute with monitoring (Linux-specific strace implementation)
            self._notify_ui("Executing sample with strace monitoring...")
            await self.db.add_event(analysis_id, "process", 0.0, "INFO", {"msg": "Execution started"})

            # Command: make executable, run with strace and capture to /tmp/strace.log
            strace_cmd = f"chmod +x {guest_sample_path} && strace -tt -o /tmp/strace.log {guest_sample_path}"
            await self.vm_manager.run_command(guest_os, strace_cmd)

            # 5. Collect and Parse behavioral results
            self._notify_ui("Collecting behavioral logs...")
            strace_log = await self.vm_manager.run_command(guest_os, "cat /tmp/strace.log")
            events = self.behaviour_monitor.parse_strace(strace_log.splitlines())

            for ev in events:
                await self.db.add_event(analysis_id, ev['type'], 0, "WARN", ev)
                self._notify_ui(f"Behavior: {ev.get('syscall', 'unknown')}", "WARN")

            # 6. Threat Scoring
            self._notify_ui("Computing threat score...")
            findings = {
                "yara_count": len(matches),
                "syscall_alerts": len(events)
            }
            score = self.threat_scorer.compute(findings)
            verdict = self.threat_scorer.get_verdict(score)
            self._notify_ui(f"Analysis complete. Verdict: {verdict} (Score: {score})", "CRITICAL" if score > 70 else "INFO")

            # Update analysis record with final score and verdict
            # Note: We need a method in Database for this, or execute directly.
            # For simplicity in this cleanup, we'll assume it's logged in events for now.
            await self.db.add_event(analysis_id, "summary", 0, "INFO", {"score": score, "verdict": verdict})

            # 7. Cleanup
            self._notify_ui("Cleaning up VM...")
            await self.vm_manager.stop_vm(guest_os)

        except Exception as e:
            self.logger.error(f"Analysis failed: {e}", exc_info=True)
            self._notify_ui(f"Error: {str(e)}", "CRITICAL")
            await self.db.add_event(analysis_id, "error", 0, "CRITICAL", {"error": str(e)})
            try:
                await self.vm_manager.stop_vm(guest_os)
            except Exception as stop_err:
                self.logger.error(f"Failed to stop VM after analysis error: {stop_err}")

        return analysis_id
