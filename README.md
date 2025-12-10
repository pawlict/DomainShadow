# DomainShadow 🕵️‍♂️ beta

**Advanced OSINT Domain Analyzer & Risk Scorer**

![Version](https://img.shields.io/badge/version-v0.5.0-blue)
![Python](https://img.shields.io/badge/python-3.8+-yellow)
![License](https://img.shields.io/badge/license-MIT-green)

---

**DomainShadow** to zaawansowane narzędzie OSINT (Open Source Intelligence) napisane w Pythonie, służące do głębokiej analizy domen internetowych.  
Agreguje dane z wielu źródeł, ocenia ryzyko bezpieczeństwa i generuje profesjonalne raporty PDF z pełną obsługą języka polskiego (UTF-8).

---

## ✨ Główne funkcjonalności

* **🔍 Głęboka Analiza DNS**  
  Rekordy A, AAAA, MX, NS oraz TXT (analiza SPF, DMARC, DKIM i innych polityk bezpieczeństwa).

* **📋 Rozszerzony WHOIS**  
  - Dane rejestratora i daty (rejestracja, wygaśnięcie, **ostatnia modyfikacja**).  
  - Informacje o sieci (*inetnum, netname, kraj, AS, organizacja*).  
  - Kontakty: **Admin, Tech, Billing, Abuse Email**.  
  - Deduplikacja numerów telefonów i adresów e-mail.

* **🌐 Archiwum Webu**  
  Integracja z **Wayback Machine** — sprawdza zarówno **pierwszą historyczną** jak i **ostatnią** migawkę strony.

* **📡 Skanowanie Infrastruktury**  
  - Integracja z **Shodan API** – wykrywanie otwartych portów, systemu operacyjnego, organizacji (ISP).  
  - Zdalne testy łączności (**Ping / HTTP**) z wielu lokalizacji przy użyciu **check-host.net** (Europa, Polska, USA, Ukraina, Rosja, Białoruś).

* **🛡️ Risk Scoring (Ocena Ryzyka)**  
  - Autorski algorytm punktacji ryzyka (0–100).  
  - Analiza wieku domeny, użycia HTTPS, ekspozycji portów administracyjnych (SSH/RDP) oraz historii domeny.  
  - Wynik z komentarzem: *niski, średni lub wysoki poziom ryzyka*.

* **📄 Raportowanie PDF**  
  - Generowanie raportów PDF i TXT.  
  - **Pełna obsługa polskich znaków (UTF-8)** – brak „czarnych pól”.  
  - Sekcje z legendą, opisem scoringu i interpretacją wyników.  
  - Wstawiany automatycznie **zrzut ekranu domeny** (z akceptacją cookies).

---

## 🧠 Legenda i Metodyka Oceny Ryzyka

W raporcie końcowym wyjaśniono m.in.:

- **Rekordy DNS:**
  - **A / AAAA** – adresy IPv4 i IPv6 hosta.
  - **MX** – serwery poczty elektronicznej.
  - **NS** – serwery nazw obsługujące domenę.
  - **TXT** – dane tekstowe (SPF, DMARC, konfiguracje weryfikacyjne).

- **Podstawa scoringu ryzyka:**
  - wiek domeny (młode domeny <30 dni obniżają wynik),
  - historia archiwalna (obecność w Wayback / Google Cache zwiększa wiarygodność),
  - konfiguracja HTTPS (brak certyfikatu obniża wynik),
  - dane WHOIS (transparentność + stabilność rejestratora),
  - ekspozycja usług (Shodan – analiza portów i hostów publicznych),
  - wyniki testów dostępności (check-host – stabilność i odpowiedź z wielu regionów).

---

## 🧩 Struktura raportu

Raport PDF zawiera:
1. Dane podstawowe i DNS.  
2. Pełny WHOIS (z inetnum, abuse, kontaktami, telefonami).  
3. Analizę HTTP/HTTPS i wyniki z check-host.net.  
4. Dane z Shodan (porty, systemy, organizacje).  
5. Archiwa (pierwsza i ostatnia migawka Wayback).  
6. Scoring ryzyka i interpretację wyników.  
7. Legendę oraz wykaz użytych źródeł OSINT.

---

## 🚀 Instalacja

### 1 Aktualizacja systemu
```bash
sudo apt-get update -y
```
### 2 Instalacja pakietów
```bash
sudo apt install -y python3 python3-venv python3-tk firefox-esr geckodriver
```
### 3 Instalacja programu
```bash
mkdir -p ~/projekts
cd ~/projekts
git clone https://github.com/pawlict/DomainShadow.git
cd DomainShadow

python3 -m venv .DomainShadow
source .DomainShadow/bin/activate

pip install --upgrade pip
pip install -r requirements.txt
```
### 4 Uruchomienie programu
```bash
python3 DomainShadow.py
```
