from gi.repository import Gtk, Adw

class Dashboard(Gtk.Box):
    """
    Dashboard view providing a summary of the current analysis results.
    Includes threat score, YARA matches, and found IOCs.
    """
    def __init__(self, **kwargs):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=20, **kwargs)
        self.set_margin_all(20)

        self._build_summary_cards()
        self._build_detail_tabs()

    def _build_summary_cards(self):
        """Creates the top-level cards for key metrics."""
        cards_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=20)
        cards_box.set_halign(Gtk.Align.CENTER)
        self.append(cards_box)

        self.score_card = self._create_card("Threat Score", "0")
        self.yara_card = self._create_card("YARA Matches", "0")
        self.ioc_card = self._create_card("IOCs Found", "0")

        cards_box.append(self.score_card)
        cards_box.append(self.yara_card)
        cards_box.append(self.ioc_card)

    def _build_detail_tabs(self):
        """Creates the notebook with tabs for different event types."""
        self.notebook = Gtk.Notebook()
        self.append(self.notebook)

        self.proc_tree = Gtk.Label(label="Process Tree details will appear here")
        self.notebook.append_page(self.proc_tree, Gtk.Label(label="Process Tree"))

        self.net_view = Gtk.Label(label="Network activity details will appear here")
        self.notebook.append_page(self.net_view, Gtk.Label(label="Network"))

        self.file_view = Gtk.Label(label="File event details will appear here")
        self.notebook.append_page(self.file_view, Gtk.Label(label="File Events"))

    def _create_card(self, title, value):
        """Helper to create a stylized metric card."""
        card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        card.add_css_class("card")
        card.set_size_request(200, 150)

        t_label = Gtk.Label(label=title)
        v_label = Gtk.Label(label=value)
        v_label.add_css_class("h1")

        card.append(t_label)
        card.append(v_label)
        return card

    def update_data(self, score, yara_count, ioc_count):
        """
        Updates the dashboard with new analysis results.
        :param score: Numeric threat score.
        :param yara_count: Number of YARA rule matches.
        :param ioc_count: Number of Indicators of Compromise found.
        """
        # Update labels in the summary cards
        self.score_card.get_last_child().set_label(str(score))
        self.yara_card.get_last_child().set_label(str(yara_count))
        self.ioc_card.get_last_child().set_label(str(ioc_count))
