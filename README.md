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

1. Öffne die App und gehe zu `Einstellungen > Konten > Dein Konto > Post-Quanten-Cryptography`.
2. Aktiviere den Schalter bei **Hybride Verschlüsselung od Signierung aktivieren (PQC + PGP)**.
3. Wähle deinen bevorzugten PQC-Algorithmen (z. B. Kyber1024).
4. Unter `PQC KEM Key Management` oder `PQC Signing Key Management` ein schlüsselpaar Generieren
5. Sende deine öffentlichen Schlüssel an die gewünschten Empfänger zur End-zu-End-Verschlüsselung
6. Aktiviere im E-Mail Editor Hybrides Signieren/Verschlüsseln oder beides.
7. Sende die E-Mail. (Für die erfolgreiche Entschlüsselung/Verifizierung müssen zuvor die Öffentlichen Schlüssel ausgetauscht sein).

📸 *Screenshots folgen hier (z. B. `docs/screenshot1.png`, `docs/screenshot2.png`)*

---

## 🧠 Hintergrund

Mit dem Aufkommen von Quantencomputern stehen klassische asymmetrische Kryptoverfahren wie RSA und ECC langfristig vor dem Aus. Post-Quantum-Kryptografie (PQC) bietet Algorithmen, die auch gegen Angriffe durch Quantencomputer sicher sind. Dieses Projekt kombiniert:

- **liboqs-java**: Bindings zu [Open Quantum Safe's](https://openquantumsafe.org/) C-Bibliothek `liboqs`.
- **Thunderbird E-Mail-Stack**: PGP-Integration mit OpenKeychain.

Durch das hybride Vorgehen bleibt die Kompatibilität mit heutigen Clients erhalten – bei gleichzeitigem Schutz vor zukünftigen Bedrohungen.

---

## 📦 Build & Installation

```bash
git clone https://github.com/DaveMcBeer/thunderbird-android-pqc.git
cd thunderbird-android-pqc
./gradlew assembleDebug
