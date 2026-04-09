cat > CONTEXT.md << 'EOF'
# Gastro Finder — Kontekst projektu

## Co to jest
Jednostronicowa aplikacja HTML (index.html) do wyszukiwania lokali gastronomicznych i firm na Google Maps z eksportem do Excel. Hostowana na GitHub Pages: https://dpekalski-cmd.github.io/gastro-finder/ (repo: dpekalski-cmd/gastro-finder).

Backend PHP (email-scraper.php) na hostingu plonpol.pl (Cyberfolks, DirectAdmin) — scrapuje emaile ze stron www lokali.

## Obecne funkcjonalności
- 4 chipy wyszukiwania: Kawiarnia, Restauracja, Rest. hotelowa, Firmy
- Adaptacyjna siatka wyszukiwania (2x2 do 5x5 punktów) z rankBy: DISTANCE
- Tryb Firmy — 16 różnych keywordów (kancelaria prawna, agencja, software house, itp.), kolumna "Branża" z tłumaczeniem typów Google na polski
- Filtry: miasto (geocoder), dzielnica, min. ocena, min. opinii, blacklista typów i nazw
- Kolumna "Wynik" — rating * log10(reviews+1), po tym sortowany ranking
- Dashboard analityczny (Chart.js) — rozkład ocen, top 5 vs reszta, scatter ocena/opinie, pokrycie dzielnic. Kwadratowe proporcje, 3 w linii.
- Email scraping (warunkowy, checkbox "Szukaj adresów e-mail") — PHP backend przeszukuje strony www + podstrony /kontakt + zgadywanie emaili przez DNS MX/SMTP
- Przycisk Stop — przerywa wyszukiwanie w dowolnym momencie
- Slider wyników do 500
- Eksport Excel (SheetJS) z kolumną Branża w trybie Firmy
- Zabezpieczenia: XSS (esc/escAttr), SSRF protection w PHP, SMTP injection prevention, CORS strict, walidacja API key, URL validation, rate limiting

## Architektura techniczna
- Frontend: czysty HTML/CSS/JS, Google Maps JavaScript API + Places API (legacy/classic), Chart.js, SheetJS
- Backend: PHP na plonpol.pl/email-scraper.php
- Hosting frontend: GitHub Pages (dpekalski-cmd/gastro-finder)
- Klucz API: każdy użytkownik wpisuje swój (overlay na starcie)

## Znane ograniczenia
- nearbySearch zwraca max 20 wyników/punkt (brak paginacji przy rankBy:DISTANCE)
- Google nie udostępnia emaili ani historii ocen
- Email scraper nie działa dla Facebook/Instagram (JavaScript rendering)
- Weryfikacja SMTP (port 25) może być zablokowana na hostingu współdzielonym
- Na mobile (iOS) działa tylko przez hosting (nie file://)
- Tryb Firmy zwraca głównie biura rachunkowe — potencjał do poprawy keywordów

## Decyzje podjęte wcześniej
- textSearch odrzucony (INVALID_REQUEST na legacy API)
- PDF export odrzucony (zła jakość wyglądu)
- nearbySearch z radius zastąpiony przez rankBy:DISTANCE (unika popularity bias)
- Filtr miasta przez porównanie nazw z geocodera (nie viewport bounds — za szerokie)
- Filtr dzielnicy odrzuca tylko gdy dzielnica jest ZNANA i INNA (nie odrzuca gdy brak danych)
- Siatka 5-punktowa dla gastro, 4-punktowa × wiele keywordów dla firm
- Facebook email scraping: próba /about, potem guessEmails przez MX/SMTP

## Tematy na przyszłość
- Backend PHP+MySQL na Cyberfolks (klucz API po stronie serwera, konta użytkowników)
- PWA (Progressive Web App) do "zainstalowania" na iOS
- Lepszy email scraping (headless browser — wymaga VPS)
- Poprawa trybu Firmy (więcej branż, lepsze filtrowanie)
EOF