"""Tiny translation layer for GhostWire (English + Turkish).

Usage: ``tr("Devices")`` returns the string in the active language. Unknown keys
fall back to the key itself, so English source strings always work even before a
Turkish entry exists. Call :func:`set_language` to switch; :func:`tr` reads the
current language lazily so it always reflects the latest choice.
"""

_LANG = "en"

# key -> {lang: translation}. English keys are the canonical source strings.
TRANSLATIONS = {
    "tr": {
        # top bar / controls
        "Start": "Başlat",
        "Pause": "Duraklat",
        "Resume": "Sürdür",
        "Stop": "Durdur",
        "Open PCAP": "PCAP Aç",
        "Save PCAP": "PCAP Kaydet",
        "Export": "Dışa Aktar",
        "Deep": "Derin",
        "iface:": "arayüz:",
        "custom BPF filter (optional)": "özel BPF filtresi (opsiyonel)",
        # tabs
        "Devices": "Cihazlar",
        "Network Map": "Ağ Haritası",
        "Live Packets": "Canlı Paketler",
        "Alerts": "Alarmlar",
        "Conversations": "Konuşmalar",
        "Event Log": "Olay Günlüğü",
        "DNS": "DNS",
        "IO Graph": "GÇ Grafiği",
        "Protocol Tree": "Protokol Ağacı",
        "Statistics": "İstatistikler",
        # stat cards
        "DEVICES": "CİHAZLAR",
        "PACKETS": "PAKETLER",
        "PROTOCOLS": "PROTOKOLLER",
        "ACTIVE 5m": "AKTİF 5dk",
        "ALERTS": "ALARMLAR",
        "THROUGHPUT": "AKTARIM",
        "UPTIME": "SÜRE",
        # menus
        "File": "Dosya",
        "Capture": "Yakalama",
        "View": "Görünüm",
        "Settings": "Ayarlar",
        "Help": "Yardım",
        "Preferences": "Tercihler",
        "Preferences...": "Tercihler...",
        "Quit": "Çıkış",
        "About": "Hakkında",
        # settings dialog
        "Search settings...": "Ayarlarda ara...",
        "Reset all to defaults": "Tümünü varsayılana sıfırla",
        "Close": "Kapat",
        "Reset": "Sıfırla",
        "Reset ALL settings to defaults?": "TÜM ayarlar varsayılana sıfırlansın mı?",
        "Settings reset. Some changes apply after restart.":
            "Ayarlar sıfırlandı. Bazı değişiklikler yeniden başlatınca uygulanır.",
        "System Network controls are unavailable on this platform.":
            "System Network kontrolleri bu platformda kullanılamıyor.",
        # device table headers
        "Type": "Tür", "MAC": "MAC", "IP": "IP", "Host/Alias": "Ana Bilgisayar/Takma",
        "Vendor": "Üretici", "OS": "İşletim Sistemi", "Risk": "Risk",
        "Protocols": "Protokoller", "Pkts": "Paket", "Last Seen": "Son Görülme",
        # misc
        "filter by MAC / IP / host / vendor / OS / tag ...":
            "MAC / IP / ana bilgisayar / üretici / OS / etikete göre filtrele ...",
        "select a device for its full dossier...":
            "tam dosyası için bir cihaz seçin...",
        "Ready": "Hazır",
    }
}


def set_language(lang: str):
    global _LANG
    _LANG = lang if lang in ("en", "tr") else "en"


def get_language() -> str:
    return _LANG


def tr(key: str) -> str:
    if _LANG == "en":
        return key
    return TRANSLATIONS.get(_LANG, {}).get(key, key)
