from gi.repository import Gtk, GLib

class LogViewer(Gtk.Box):
    """
    Real-time log viewer widget.
    Displays application and analysis logs in a scrollable terminal-like area.
    """
    def __init__(self, **kwargs):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=5, **kwargs)
        self.set_size_request(-1, 200)

        # Toolbar with controls
        toolbar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=5)
        self.append(toolbar)

        title = Gtk.Label(label="LOG STREAM")
        title.add_css_class("caption")
        toolbar.append(title)

        self.pause_btn = Gtk.ToggleButton(label="Pause")
        toolbar.append(self.pause_btn)

        self.clear_btn = Gtk.Button(label="Clear")
        self.clear_btn.connect("clicked", lambda _: self.buffer.set_text(""))
        toolbar.append(self.clear_btn)

        # Log text area
        scrolled = Gtk.ScrolledWindow()
        scrolled.set_vexpand(True)
        self.append(scrolled)

        self.log_text = Gtk.TextView()
        self.log_text.set_editable(False)
        self.log_text.set_cursor_visible(False)
        self.log_text.add_css_class("terminal")
        scrolled.set_child(self.log_text)

        self.buffer = self.log_text.get_buffer()

    def append_log(self, message, severity="INFO"):
        """
        Appends a new message to the log buffer.
        :param message: The log message text.
        :param severity: Severity level (INFO, WARN, ERROR, CRITICAL).
        """
        if self.pause_btn.get_active():
            return

        end_iter = self.buffer.get_end_iter()
        prefix = f"[{severity}] "
        self.buffer.insert(end_iter, f"{prefix}{message}\n")

        # Auto-scroll to the bottom
        adj = self.log_text.get_vadjustment()
        GLib.idle_add(lambda: adj.set_value(adj.get_upper() - adj.get_page_size()))
