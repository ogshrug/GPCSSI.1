from gi.repository import Gtk, Adw

class ReportView(Gtk.Box):
    """
    Detailed report view for a completed analysis.
    Displays found Indicators of Compromise (IOCs) and other metadata.
    """
    def __init__(self, **kwargs):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=10, **kwargs)
        self.set_margin_all(20)

        self.append(Gtk.Label(label="Analysis Report Details"))

        # IOC Table using ListBox
        self.ioc_list = Gtk.ListBox()
        self.ioc_list.set_selection_mode(Gtk.SelectionMode.NONE)

        scrolled = Gtk.ScrolledWindow()
        scrolled.set_vexpand(True)
        scrolled.set_child(self.ioc_list)
        self.append(scrolled)

        # Action buttons
        button_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        button_box.set_halign(Gtk.Align.END)
        self.append(button_box)

        self.export_btn = Gtk.Button(label="Export to PDF")
        button_box.append(self.export_btn)

    def add_ioc(self, ioc_type, value):
        """
        Adds an IOC entry to the report view.
        :param ioc_type: Type of IOC (e.g., 'ip', 'domain', 'hash').
        :param value: The IOC value.
        """
        row = Adw.ActionRow(title=value, subtitle=ioc_type)
        self.ioc_list.append(row)

    def clear(self):
        """Clears all IOCs from the view."""
        while row := self.ioc_list.get_first_child():
            self.ioc_list.remove(row)
