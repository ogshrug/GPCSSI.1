import os
import subprocess
import threading
import asyncio
import logging
from gi.repository import Gtk, Adw, Gio, GLib
from ui.dashboard import Dashboard
from ui.log_viewer import LogViewer
from ui.yara_editor import YaraEditor
from ui.report_view import ReportView
from storage.db import Database
from core.orchestrator import Orchestrator

class MainWindow(Adw.ApplicationWindow):
    """
    Main application window for Malware Sandbox.
    Manages the UI layout, VM selection, and coordinates analysis tasks.
    """
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.set_title("Malware Sandbox")
        self.set_default_size(1200, 900)

        # Initialize core components
        self.db = Database()
        self.orchestrator = Orchestrator(self.db, ui_callback=self._append_log)
        self._db_ready = threading.Event()

        self._build_ui()
        self._start_db_init()
        self._update_vm_list()
        self._validate_submit()

    def _build_ui(self):
        """Constructs the main UI layout."""
        self.main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self.set_content(self.main_box)

        # Header with navigation
        self.header = Adw.HeaderBar()
        self.main_box.append(self.header)

        # Action bar for submission and VM preparation
        upload_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        upload_box.set_margin_all(10)
        upload_box.set_halign(Gtk.Align.CENTER)

        self.upload_btn = Gtk.Button(label="Submit File for Analysis")
        self.upload_btn.add_css_class("suggested-action")
        self.upload_btn.connect("clicked", self._on_submit_clicked)
        upload_box.append(self.upload_btn)

        gui_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=5)
        gui_box.set_valign(Gtk.Align.CENTER)
        gui_label = Gtk.Label(label="Run with GUI")
        self.gui_switch = Gtk.CheckButton()
        gui_box.append(gui_label)
        gui_box.append(self.gui_switch)
        upload_box.append(gui_box)

        self.prepare_btn = Gtk.Button(label="Prepare New VM")
        self.prepare_btn.connect("clicked", self._on_prepare_vm_clicked)
        upload_box.append(self.prepare_btn)

        self.main_box.append(upload_box)

        # Target selection (VM and Snapshot)
        selection_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        selection_box.set_halign(Gtk.Align.CENTER)
        selection_box.set_margin_bottom(10)

        selection_box.append(Gtk.Label(label="Target VM:"))
        self.vm_dropdown = Gtk.DropDown()
        self.vm_dropdown.connect("notify::selected", self._on_vm_selected)
        selection_box.append(self.vm_dropdown)

        selection_box.append(Gtk.Label(label="Snapshot:"))
        self.snapshot_dropdown = Gtk.DropDown()
        self.snapshot_dropdown.connect("notify::selected", self._on_snapshot_selected)
        selection_box.append(self.snapshot_dropdown)

        self.main_box.append(selection_box)

        # Main content area (Sidebar + Stack)
        paned = Gtk.Paned(orientation=Gtk.Orientation.HORIZONTAL)
        paned.set_wide_handle(True)
        self.main_box.append(paned)

        # Sidebar for recent analyses
        sidebar = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        sidebar.set_size_request(250, -1)
        sidebar.add_css_class("sidebar")
        paned.set_start_child(sidebar)

        sidebar.append(Gtk.Label(label="RECENT ANALYSES"))
        self.analysis_list = Gtk.ListBox()
        sidebar.append(self.analysis_list)

        # Content stack for different views
        self.stack = Gtk.Stack()
        self.stack.set_transition_type(Gtk.StackTransitionType.SLIDE_LEFT_RIGHT)
        paned.set_end_child(self.stack)

        self.dashboard = Dashboard()
        self.stack.add_titled(self.dashboard, "dashboard", "Dashboard")

        self.yara_editor = YaraEditor()
        self.stack.add_titled(self.yara_editor, "yara", "YARA Rules")

        self.report_view = ReportView()
        self.stack.add_titled(self.report_view, "reports", "Reports")

        # Bottom log viewer
        self.log_viewer = LogViewer()
        self.main_box.append(self.log_viewer)

        # Navigation switcher in header
        switcher = Gtk.StackSwitcher()
        switcher.set_stack(self.stack)
        self.header.set_title_widget(switcher)

    def _start_db_init(self):
        """Initializes the database in a background thread."""
        def init_db():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                loop.run_until_complete(self.db.connect())
                self._db_ready.set()
                self._append_log("Database initialized.", "INFO")
            except Exception as e:
                self._append_log(f"Database initialization failed: {e}", "CRITICAL")

        threading.Thread(target=init_db, daemon=True).start()

    def _on_submit_clicked(self, btn):
        """Handles the 'Submit' button click by opening a file chooser."""
        dialog = Gtk.FileChooserDialog(
            title="Select File for Analysis",
            parent=self,
            action=Gtk.FileChooserAction.OPEN,
        )
        dialog.add_button("_Cancel", Gtk.ResponseType.CANCEL)
        dialog.add_button("_Open", Gtk.ResponseType.ACCEPT)

        dialog.connect("response", self._on_file_chooser_response)
        dialog.present()

    def _on_file_chooser_response(self, dialog, response):
        """Processes the file selection from the dialog."""
        if response == Gtk.ResponseType.ACCEPT:
            file_path = dialog.get_file().get_path()
            run_gui = self.gui_switch.get_active()

            vm_item = self.vm_dropdown.get_selected_item()
            snap_item = self.snapshot_dropdown.get_selected_item()

            vm_name = vm_item.get_string() if vm_item else None
            snap_name = snap_item.get_string() if snap_item else None

            if not self._db_ready.wait(timeout=5):
                self._append_log("Database not ready. Please try again in a moment.", "ERROR")
            else:
                self._start_analysis(file_path, vm_name, snap_name, run_gui)
        dialog.destroy()

    def _start_analysis(self, filename, vm_name, snap_name, run_gui):
        """Starts the analysis process in a background thread."""
        self._append_log(f"Submitting {filename} for analysis on {vm_name} ({snap_name})...", "INFO")

        def run_async():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(self.orchestrator.run_analysis(
                filename,
                guest_os=vm_name,
                snapshot_name=snap_name,
                run_gui=run_gui
            ))
            GLib.idle_add(self._on_analysis_complete)

        threading.Thread(target=run_async, daemon=True).start()

    def _on_analysis_complete(self):
        """Updates the UI after an analysis task finishes."""
        self._append_log("Analysis complete. Check the dashboard for results.", "INFO")
        # Placeholder for dynamic UI update
        self.dashboard.update_data(87, 4, 12)

    def _on_prepare_vm_clicked(self, btn):
        """Launches the external VM preparation script."""
        script = os.path.join(os.path.dirname(__file__), "prepare_vm.sh")
        try:
            subprocess.Popen(["bash", script], cwd=os.path.dirname(script))
        except Exception as e:
            self._append_log(f"Failed to launch VM preparation script: {e}", "ERROR")

    def _append_log(self, msg, sev="INFO"):
        """Safely appends a message to the log viewer from any thread."""
        GLib.idle_add(self.log_viewer.append_log, msg, sev)

    def _update_vm_list(self):
        """Refreshes the target VM dropdown list."""
        try:
            vms = self.orchestrator.vm_manager.list_vms()
            vms = [""] + sorted(vms)
            self.vm_dropdown.set_model(Gtk.StringList.new(vms))
        except Exception as e:
            self._append_log(f"Error listing VMs: {e}", "CRITICAL")

    def _on_vm_selected(self, dropdown, pspec):
        """Updates the snapshot list when a VM is selected."""
        selected_item = dropdown.get_selected_item()
        if selected_item:
            vm_name = selected_item.get_string()
            if vm_name:
                try:
                    snapshots = self.orchestrator.vm_manager.list_snapshots(vm_name)
                    snapshots = [""] + sorted(snapshots)
                    self.snapshot_dropdown.set_model(Gtk.StringList.new(snapshots))
                except Exception as e:
                    self._append_log(f"Error listing snapshots for {vm_name}: {e}", "CRITICAL")
                    self.snapshot_dropdown.set_model(Gtk.StringList.new([""]))
            else:
                self.snapshot_dropdown.set_model(Gtk.StringList.new([""]))
        self._validate_submit()

    def _on_snapshot_selected(self, dropdown, pspec):
        """Re-validates the submission state when a snapshot is selected."""
        self._validate_submit()

    def _validate_submit(self):
        """Enables or disables the submission button based on current selections."""
        vm_selected = False
        snap_selected = False

        vm_item = self.vm_dropdown.get_selected_item()
        if vm_item and vm_item.get_string():
            vm_selected = True

        snap_item = self.snapshot_dropdown.get_selected_item()
        if snap_item and snap_item.get_string():
            snap_selected = True

        self.upload_btn.set_sensitive(vm_selected and snap_selected)
