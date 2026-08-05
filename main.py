#!/usr/bin/env python3
"""GhostWire (PassiveEye) entry point. See README.md for usage."""
import sys
import os
import argparse


def check_privileges(offline: bool = False):
    """Check if running with sufficient privileges for packet capture.

    Offline PCAP analysis needs no elevated privileges, so it is always allowed.
    """
    if offline:
        return True

    if os.name == "posix":
        if hasattr(os, "geteuid") and os.geteuid() != 0:
            print("\n[!] GhostWire needs root/sudo for live raw packet capture.")
            print("    Run with:  sudo python main.py")
            print("    (or analyse a capture file with:  python main.py --pcap file.pcap)\n")
            return False
        return True

    if os.name == "nt":
        # Windows: scapy uses Npcap; admin is needed for promiscuous mode.
        try:
            import ctypes
            if ctypes.windll.shell32.IsUserAnAdmin() == 0:
                print("\n[!] GhostWire on Windows requires Administrator privileges")
                print("    and Npcap (https://npcap.com/) installed.")
                print("    Right-click your shell and choose 'Run as administrator'.\n")
                return False
        except Exception:
            pass
        return True

    return True


def main():
    parser = argparse.ArgumentParser(
        description="GhostWire - Passive Network Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-i", "--interface",
        help="Network interface to capture on (default: all)",
    )
    parser.add_argument(
        "--db",
        default="passive_scanner.db",
        help="SQLite database path (default: passive_scanner.db)",
    )
    parser.add_argument(
        "--pcap",
        help="Analyse a saved capture file offline (no root required)",
    )
    parser.add_argument(
        "--deep",
        action="store_true",
        help="Start in Deep Capture Mode (dissect all IP/TCP/UDP, not just discovery)",
    )
    parser.add_argument(
        "--no-splash",
        action="store_true",
        help="Skip the boot splash animation",
    )
    args = parser.parse_args()

    if not check_privileges(offline=bool(args.pcap)):
        sys.exit(1)

    # Import Qt lazily so --help stays fast.
    from PyQt5.QtWidgets import QApplication
    from PyQt5.QtCore import Qt
    from PyQt5.QtGui import QFont

    from core.settings import get_settings
    from core.i18n import set_language
    from gui.fonts import load_fonts
    from gui.main_window import MainWindow
    from gui.splash import BootSplash

    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)

    app = QApplication(sys.argv)
    app.setApplicationName("GhostWire")
    app.setOrganizationName("CyberSecClub")

    settings = get_settings()
    set_language(settings.get("locale.language", "en"))
    load_fonts()  # register bundled pixel fonts (accent use)

    font = QFont("JetBrains Mono", settings.get("appearance.font_size", 10))
    font.setStyleHint(QFont.Monospace)
    app.setFont(font)

    # CLI flags override the stored default for this run.
    if args.deep:
        settings.set("capture.deep", True, save=False)

    window = MainWindow(db_path=args.db, deep=args.deep or settings.get("capture.deep", False),
                        pcap=args.pcap, settings=settings)

    if args.interface:
        combo = window._iface_combo
        for i in range(combo.count()):
            if combo.itemText(i) == args.interface:
                combo.setCurrentIndex(i)
                break

    def show_main():
        window.show()
        if args.pcap:
            window.load_pcap(args.pcap)

    if args.no_splash:
        show_main()
    else:
        splash = BootSplash()
        # Center the splash on the primary screen.
        screen = app.primaryScreen().geometry()
        splash.move(
            screen.center().x() - splash.width() // 2,
            screen.center().y() - splash.height() // 2,
        )
        splash.finished.connect(show_main)
        splash.show()

    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
