# Thunderbird Android PQC Edition

**Post-Quantum Secure Email für Android – mit hybrider Verschlüsselung und Signatur.**

Dieses Projekt ist ein Fork von Mozillas [thunderbird-android](https://github.com/mozilla-mobile/thunderbird-android), erweitert um Post-Quantum-Kryptografie (PQC) durch die Integration der [`liboqs-java`](https://github.com/open-quantum-safe/liboqs-java) Bibliothek. Ziel ist es, E-Mail-Kommunikation auf mobilen Geräten bereits heute gegen Angriffe durch zukünftige Quantencomputer abzusichern.

---

## ✨ Features

- 🔐 **Hybride Verschlüsselung**: Kombination aus klassischem PGP (RSA/ElGamal) + PQC-Algorithmen (z. B. Kyber).
- ✍️ **Hybride Signatur**: Digitale Signaturen mit klassischem Verfahren + PQC-Verfahren (z. B. Dilithium).
- 📱 **Nahtlose Thunderbird-UX**: Die gewohnte Benutzeroberfläche bleibt erhalten.
- 🔌 **liboqs-java Integration**: Bindings zu liboqs via Java, nativ integriert in den Kryptografie-Stack.

---

## 🧪 Aktivierung der PQC-Funktionen

> ⚙️ Du kannst die PQC-Features in den Einstellungen von Thunderbird aktivieren. Hier ist eine kurze Schritt-für-Schritt-Anleitung mit Screenshots:

---

### 1. PQC-Einstellungen öffnen  
`Einstellungen > Konten > Dein Konto > Post-Quantum-Cryptography`
Feature aktivieren, Schlüsselgenerieren, Öffentliche Schlüssel an gewünschte Empfänger Mail senden
<img src="docs/PQC%20einstellungen%20und%20Schl%C3%BCsselverwaltung.png" width="500"/>
---

### 2. PQC-Verschlüsselung oder -Signatur aktivieren  
Nach
    - **KEM aktivierung** für Verschlüsselung  
    - **Sign-Only aktivierung** für digitale Signatur  
    - Wunschalgorithmus auswählen (z. B. Dilithium, Falcon)
Im E-Mail-Editor PQC aktivieren  
    - Öffne eine neue Nachricht und aktiviere PQC/PGP-Modi:  
<img src="docs/Activate%20PQC%20in%20Maileditor.jpg" width="300"/>

 Wenn aktiv:
<img src="docs/Email%20signieren.jpg" width="300"/>
<img src="docs/E Mail verschlüsseln.jpg" width="300"/>

---

### 4. Nachricht absenden – Ergebnisanzeige

- ✅ **Hybrid-verschlüsselte Nachricht erfolgreich entschlüsselt:**  
  <img src="docs/Email%20entschl%C3%BCsselt.jpg" width="400"/>

- ✅ **Hybrid-Signatur erfolgreich verifiziert:**  
  <img src="docs/Email%20verifiziert.jpg" width="400"/>

---

### 5. Fehlermeldungen bei Problemen

- ❌ **Entschlüsselung fehlgeschlagen:**  
  <img src="docs/failed_encryption.jpg" width="400"/>

- ❌ **Signaturprüfung fehlgeschlagen:**  
  <img src="docs/failed_signature.jpg" width="400"/>

---

## 🧠 Hintergrund

Mit dem Aufkommen von Quantencomputern stehen klassische asymmetrische Kryptoverfahren wie RSA und ECC langfristig vor dem Aus. Post-Quantum-Kryptografie (PQC) bietet Algorithmen, die auch gegen Angriffe durch Quantencomputer sicher sind. Dieses Projekt kombiniert:

- **liboqs-java**: Bindings zu [Open Quantum Safe's](https://openquantumsafe.org/) C-Bibliothek `liboqs`.
- **Thunderbird E-Mail-Stack**: PGP-Integration mit Bouncycastle.

Durch das hybride Vorgehen bleibt die Kompatibilität mit heutigen Clients erhalten – bei gleichzeitigem Schutz vor zukünftigen Bedrohungen.


---

## 📦 Build & Installation

> 🛠️ **Voraussetzungen:**
>
> - **Android Studio (Empfohlen)** – inklusive korrekt konfiguriertem Android SDK
> - Alternativ: Manuelles Setzen des SDK-Pfads in `local.properties`:
>   ```properties
>   sdk.dir=/Pfad/zum/android/sdk
>   ```
>   Beispiel für Windows:
>   ```properties
>   sdk.dir=C:\\Users\\dein-benutzername\\AppData\\Local\\Android\\Sdk
>   ```

### 🔧 Kompilierung (Debug-Build):

```bash
git clone https://github.com/DaveMcBeer/thunderbird-android-pqc.git
cd thunderbird-android-pqc
./gradlew assembleDebug
