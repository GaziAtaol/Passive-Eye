#!/usr/bin/env python3
"""PassiveEye entry point. See README.md for usage."""
import sys
import os
import argparse


def check_privileges():
    """Check if running with sufficient privileges for packet capture."""
    if os.name == "posix":
        if hasattr(os, "geteuid") and os.geteuid() != 0:
            print("\n[!] PassiveEye needs root/sudo for raw packet capture.")
            print("    Run with:  sudo python main.py\n")
            return False
        return True

    if os.name == "nt":
        # Windows: scapy uses Npcap; admin is needed for promiscuous mode.
        try:
            import ctypes
            if ctypes.windll.shell32.IsUserAnAdmin() == 0:
                print("\n[!] PassiveEye on Windows requires Administrator privileges")
                print("    and Npcap (https://npcap.com/) installed.")
                print("    Right-click your shell and choose 'Run as administrator'.\n")
                return False
        except Exception:
            pass
        return True

    return True


def main():
    parser = argparse.ArgumentParser(
        description="PassiveEye - Passive Network Scanner",
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
    args = parser.parse_args()

    if not check_privileges():
        sys.exit(1)

    # Import Qt lazily so --help stays fast.
    from PyQt5.QtWidgets import QApplication
    from PyQt5.QtCore import Qt
    from PyQt5.QtGui import QFont

    from gui.main_window import MainWindow

    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)

    app = QApplication(sys.argv)
    app.setApplicationName("PassiveEye")
    app.setOrganizationName("CyberSecClub")

    font = QFont("Times New Roman", 10)
    font.setStyleHint(QFont.Serif)
    app.setFont(font)

    window = MainWindow(db_path=args.db)

    if args.interface:
        combo = window._iface_combo
        for i in range(combo.count()):
            if combo.itemText(i) == args.interface:
                combo.setCurrentIndex(i)
                break

    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
