# Gastro Finder — Kontekst projektu

## Co to jest
Jednostronicowa aplikacja HTML (index.html, ~2500 linii) do wyszukiwania lokali gastronomicznych i firm na Google Maps, z analityką, widokiem skupisk i eksportem do Excel. Hostowana na GitHub Pages: https://dpekalski-cmd.github.io/gastro-finder/ (repo: dpekalski-cmd/gastro-finder).

Backend PHP (email-scraper.php) na hostingu plonpol.pl (Cyberfolks, DirectAdmin) — scrapuje emaile ze stron www lokali.

## Obecne funkcjonalności

### Wyszukiwanie
- 5 chipów typu: Kawiarnia, Restauracja, Rest. hotelowa, **Całe gastro**, Firmy
- `gastro_all` (Całe gastro) — type `food` + 10 keywordów (restauracja, kawiarnia, bistro, bar, pub, pizzeria, sushi, kebab, burgers, bakery)
- Tryb Firmy — type `establishment` + 16 keywordów (kancelaria prawna, agencja marketingowa/reklamowa/PR/eventowa/nieruchomości, software house, firma IT/szkoleniowa/budowlana, doradztwo consulting, biuro architektoniczne/projektowe, salon samochodowy, hotel boutique, piekarnia rzemieślnicza); kolumna „Branża" z tłumaczeniem typów Google na polski
- Adaptacyjna siatka wyszukiwania z `rankBy: DISTANCE` — rozmiar zależy od przekątnej viewportu geocodera: <5 km → 2×2, <12 km → 3×3, <25 km → 4×4, powyżej → 5×5. Zagęszczana gdy user chce >80 wyników (min. 4×4) lub >150 (min. 5×5). W trybie wielokeywordowym (Firmy) używane są max 4 punkty siatki × wszystkie keywordy
- Slider wyników 10–500, przycisk Stop (`searchAborted`) przerywa w dowolnym momencie
- Pasek debug (`#debugBar`) pokazuje na żywo krok wyszukiwania, chowa się po zakończeniu

### Filtry
- Miasto — porównanie `locality` z geocodera z `locality` lokalu (odrzuca inne miasta)
- Dzielnica — odrzuca tylko gdy dzielnica lokalu jest ZNANA i INNA (brak danych = akceptuj)
- `reverseGeocodeDistrict()` — fallback reverse-geocoding gdy Place Details nie zwróciło dzielnicy
- Min. ocena (3.0–5.0), min. liczba opinii (0–500) — `passesQualityFilter`
- Blacklisty typów i nazw (`isBlacklisted`) — osobne dla gastro i firm

### Widoki (przełącznik „Tryb widoku": Lista / Skupiska)
- **Lista** — klasyczne markery numerowane + tabela z rankingiem
- **Skupiska** — klasteryzacja geograficzna:
  - Algorytm zachłanny: dla każdego punktu liczymy sąsiadów w promieniu R (haversine), bierzemy punkt o największej gęstości, tworzymy skupisko, usuwamy członków z puli, powtarzamy
  - Parametry: promień 30–500 m (domyślnie 100), min. lokali w skupisku 2–12 (domyślnie 3) — zmiana slidera przelicza na żywo (`recomputeClusters`)
  - Na mapie: koła Circle kolorowane wg wielkości (7+ czerwone, 5–6 pomarańczowe, 4 żółte, 2–3 zielone) + InfoWindow z licznikiem i śr. oceną; lokale poza skupiskami jako szare kropki
  - Legenda skupisk w sidebarze
  - Klik w skupisko → pan/zoom, pasek info nad tabelą, filtrowanie tabeli do członków skupiska, przycisk „Eksportuj skupisko do Excel" (osobny arkusz + zakładka Info z metadanymi)
  - Tabela w trybie skupisk ma badge `S1`, `S2`… przy lokalach przypisanych do skupisk

### Analityka (Chart.js)
- 4 karty summary: liczba lokali, śr. ocena, łącznie opinii, śr. Wynik
- 4 wykresy w siatce 3-w-linii, kwadratowe proporcje:
  1. Rozkład ocen (histogram, 6 koszyków)
  2. Top 5 vs pozostałe (śr. ocena i śr. opinii ÷100)
  3. Rozkład Wyniku (bubble chart: opinie × ocena, rozmiar = względna liczba opinii)
  4. Pokrycie dzielnic (doughnut ≤8 dzielnic, poziomy bar powyżej)
- Kolumna „Wynik" = `rating × log10(reviews+1)` — po tym sortowany ranking

### Pozostałe
- Email scraping (warunkowy, checkbox „Szukaj adresów e-mail") — PHP backend przeszukuje stronę główną → podstrony /kontakt (max 3, wykrywane z linków lub zgadywane) → guessEmails przez DNS MX + weryfikacja SMTP RCPT TO
- Eksport Excel (SheetJS) — arkusz danych + arkusz „Informacje"; kolumna Branża w trybie Firmy
- Klucz API wpisywany przez użytkownika (overlay na starcie), ładowany z `libraries=places`
- Zabezpieczenia: XSS (`esc()` — jedna implementacja escapująca `& < > " '`), walidacja `https?://` przy linkach, walidacja formatu klucza API, walidacja emaili z backendu, sanityzacja nazwy pliku eksportu

## Backend: email-scraper.php v5 (hardening)
Wersja v4 miała lukę SSRF: `max_redirects => 5` w stream wrapperze oznaczało, że PHP samo podążało za przekierowaniami **bez ponownej walidacji** — `evil.com` → 302 → `http://127.0.0.1/` przechodziło przez całą kontrolę. v5:
- przekierowania obsługiwane ręcznie (cURL, `FOLLOWLOCATION=false`), każdy hop przez `validateFetchUrl()`, max 3 hopy
- sprawdzane **wszystkie** rekordy A i AAAA (v4: tylko pierwszy adres IPv4 z `gethostbyname`, więc `::1` i `fd00::/8` przechodziły); IPv4-mapped IPv6 (`::ffff:127.0.0.1`) rozwijane i sprawdzane jako IPv4
- fail-closed przy błędzie DNS (v4 przepuszczało nierozwiązywalne hosty)
- whitelist portów 80/443 (v4 pozwalało na `host:22` → skanowanie portów)
- rozszerzone zakresy: `0.0.0.0/8`, `192.0.0.0/24`, `198.18.0.0/15`, TEST-NET, multicast/broadcast
- walidacja IP hosta MX przed połączeniem SMTP (rekord MX mógł wskazywać na localhost)
- weryfikacja certyfikatu TLS włączona, z fallbackiem przy braku CA bundle na hostingu
- rate limiting z `flock()` (v4 miał wyścig read-then-write), liczony **przed** walidacją URL, żeby endpoint nie służył jako darmowy resolver DNS
- budżet czasu 12 s na całe żądanie (frontend przerywa po 15 s, więc odpowiedź przychodzi zawsze)
- `display_errors=0` — pojedynczy warning psuł JSON i frontend wywalał się na `resp.json()`
- linki do podstron: dopasowanie hosta zamiast `strpos()` (v4 przepuszczało `example.com.evil.pl`)
- `rawurldecode` zamiast `urldecode` — ten drugi zamieniał `+` na spację i psuł adresy typu `jan+kontakt@domena.pl`

## Architektura techniczna
- Frontend: czysty HTML/CSS/JS, Google Maps JavaScript API + Places API (legacy/classic), Chart.js 4.4.1, SheetJS 0.18.5
- Backend: PHP na plonpol.pl/email-scraper.php
- Hosting frontend: GitHub Pages (dpekalski-cmd/gastro-finder)
- Paleta kolorów: Claude.ai (akcent #D97757), font Inter

## Znane ograniczenia
- Zmiana klucza wyszukiwania Google: `google.maps.Geocoder` wymaga **osobno włączonego Geocoding API** w Google Cloud Console (oraz obecności Geocoding API na liście *API restrictions* klucza). Bez tego geokoder zwraca `REQUEST_DENIED` i wyszukiwanie nie startuje wcale
- nearbySearch zwraca max 20 wyników/punkt (brak paginacji przy rankBy:DISTANCE)
- Google nie udostępnia emaili ani historii ocen
- Email scraper nie działa dla Facebook/Instagram (JavaScript rendering)
- Weryfikacja SMTP (port 25) może być zablokowana na hostingu współdzielonym
- **Na mobile (≤700px) mapa jest ukryta przez CSS `!important`** — widok Skupiska jest tam bezużyteczny (`recomputeClusters` wymaga mapy); po wyszukiwaniu na mobile rysowanie markerów/klastrów jest pomijane
- Zakładki mobilne (`.mobile-tabs`) są ukryte — układ na mobile jest jednokolumnowy, przewijalny; `switchTab()` pozostał w kodzie jako martwy
- Na mobile (iOS) działa tylko przez hosting (nie file://)
- Tryb Firmy zwraca głównie biura rachunkowe — potencjał do poprawy keywordów

## Decyzje podjęte wcześniej
- textSearch odrzucony (INVALID_REQUEST na legacy API)
- PDF export odrzucony (zła jakość wyglądu)
- nearbySearch z radius zastąpiony przez rankBy:DISTANCE (unika popularity bias)
- Filtr miasta przez porównanie nazw z geocodera (nie viewport bounds — za szerokie)
- Filtr dzielnicy odrzuca tylko gdy dzielnica jest ZNANA i INNA (nie odrzuca gdy brak danych)
- Siatka pełna dla gastro (jeden keyword), 4-punktowa × wiele keywordów dla firm
- Facebook email scraping: próba /about, potem guessEmails przez MX/SMTP
- Klasteryzacja własna (zachłanna, haversine) zamiast MarkerClusterer — potrzebne były realne promienie w metrach i eksport członków skupiska
- **Heatmapa — usunięta.** Google wycofał `visualization.HeatmapLayer` w Maps JS 3.65 (maj 2026); własna implementacja canvasowa nie dawała zadowalającej jakości. Wzór `ocena × log10(opinie+1)` pozostaje — zasila kolumnę „Wynik”, sortowanie i eksport
- Klasteryzacja liczona na siatce przestrzennej (komórka = promień, sąsiedzi w oknie 3×3), z punktowym odświeżaniem liczników po wycięciu skupiska — semantyka zachłanna identyczna jak w wersji naiwnej, ale bez O(n³). Zweryfikowane: te same skupiska, 100–600× szybciej (500 lokali: 5,1 s → 8 ms)
- Żądania do Places API idą równolegle z limitem współbieżności (4 dla nearbySearch, 6 dla getDetails) + retry na `OVER_QUERY_LIMIT`; sekwencyjne pobieranie było wąskim gardłem całej aplikacji

## Tematy na przyszłość
- Backend PHP+MySQL na Cyberfolks (klucz API po stronie serwera, konta użytkowników)
- PWA (Progressive Web App) do „zainstalowania" na iOS
- Lepszy email scraping (headless browser — wymaga VPS)
- Poprawa trybu Firmy (więcej branż, lepsze filtrowanie)
- Widok skupisk na mobile (wymaga pokazania mapy na małych ekranach)
