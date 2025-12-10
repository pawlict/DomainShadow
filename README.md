# DomainShadow 🕵️‍♂️ beta

**Advanced OSINT Domain Analyzer & Risk Scorer**

![Version](https://img.shields.io/badge/version-v0.5.0-blue) ![Python](https://img.shields.io/badge/python-3.8+-yellow) ![License](https://img.shields.io/badge/license-MIT-green)

**DomainShadow** to zaawansowane narzędzie OSINT (Open Source Intelligence) napisane w Pythonie, służące do głębokiej analizy domen internetowych. Agreguje dane z wielu źródeł, ocenia ryzyko bezpieczeństwa i generuje profesjonalne raporty PDF.

## ✨ Główne funkcjonalności

*   **🔍 Głęboka Analiza DNS**: Rekordy A, AAAA, MX, NS oraz TXT (weryfikacja SPF, DMARC, DKIM).
*   **📋 Rozszerzony WHOIS**:
    *   Dane rejestratora i daty (rejestracja, wygaśnięcie, *ostatnia modyfikacja*).
    *   Informacje o sieci (inetnum, netname, kraj).
    *   Kontakty (Admin, Tech, Billing) oraz **Abuse Email**.
    *   Deduplikacja numerów telefonów i emaili.
*   **🌐 Archiwum Webu**: Integracja z **Wayback Machine** – sprawdza zarówno *pierwszą* (historyczną), jak i *ostatnią* migawkę strony.
*   **📡 Skanowanie Infrastruktury**:
    *   Integracja z **Shodan API** (wykrywanie otwartych portów, OS, ISP).
    *   Zdalne testy łączności (Ping/HTTP) z wielu lokalizacji via **check-host.net**.
*   **🛡️ Risk Scoring (Ocena Ryzyka)**:
    *   Autorski algorytm oceniający domenę w skali 0-100.
    *   Analiza wieku domeny, konfiguracji HTTPS, otwartych portów (SSH/RDP) i historii.
*   **📄 Raportowanie PDF**:
    *   Generowanie estetycznych raportów PDF.
    *   **Pełna obsługa polskich znaków (UTF-8)** (brak "czarnych pól").
    *   Sekcje z legendą i wyjaśnieniami dla nietechnicznych odbiorców.

## 🚀 Instalacja

1.  Sklonuj repozytorium:
    ```
    git clone https://github.com/pawlict/DomainShadow.git
    cd DomainShadow
    ```

2.  Zainstaluj wymagane biblioteki:
    ```
    pip install requests python-whois dnspython reportlab
    ```
    *(Opcjonalnie dla screenshotów: `pip install selenium`)*

## 🖥️ Użycie

Uruchom narzędzie z interfejsem graficznym (GUI):

