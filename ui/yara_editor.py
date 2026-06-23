from gi.repository import Gtk

class YaraEditor(Gtk.Box):
    """
    Simplified editor for creating and modifying YARA rules.
    """
    def __init__(self, **kwargs):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=10, **kwargs)
        self.set_margin_all(20)

        self._build_header()
        self._build_editor()

        # Status indicator
        self.status_label = Gtk.Label(label="Ready")
        self.append(self.status_label)

    def _build_header(self):
        """Creates the header with title and save button."""
        header = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        self.append(header)

        label = Gtk.Label(label="YARA Rule Editor")
        label.add_css_class("h2")
        header.append(label)

        self.save_btn = Gtk.Button(label="Save Rule")
        self.save_btn.set_halign(Gtk.Align.END)
        self.save_btn.set_hexpand(True)
        self.save_btn.add_css_class("suggested-action")
        header.append(self.save_btn)

    def _build_editor(self):
        """Creates the main text editing area."""
        scrolled = Gtk.ScrolledWindow()
        scrolled.set_vexpand(True)
        self.append(scrolled)

        self.text_view = Gtk.TextView()
        self.text_view.set_monospace(True)
        self.text_view.set_left_margin(10)
        self.text_view.set_top_margin(10)
        scrolled.set_child(self.text_view)

    def get_text(self):
        """Returns the current content of the editor."""
        buffer = self.text_view.get_buffer()
        start, end = buffer.get_bounds()
        return buffer.get_text(start, end, True)

    def set_text(self, text):
        """Sets the content of the editor."""
        self.text_view.get_buffer().set_text(text)
