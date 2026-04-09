cat > CLAUDE.md << 'EOF'
# Gastro Finder — Instrukcje

## Projekt
Aplikacja do wyszukiwania lokali gastronomicznych i firm via Google Maps API.
Pełny kontekst w CONTEXT.md.

## Architektura
- index.html — cały frontend (single-file HTML app, ~1900 linii)
- email-scraper.php — backend PHP na plonpol.pl (hosting Cyberfolks, DirectAdmin)
- Hosting frontend: GitHub Pages (dpekalski-cmd.github.io/gastro-finder)

## Zasady pracy
- NIGDY nie psuj istniejącej funkcjonalności dodając nowe
- Wszystkie dane z API escapuj przez esc()/escAttr() 
- Waliduj URL-e (tylko https?://)
- Testuj pod kątem mobile (width <= 700px)
- Język interfejsu: polski
- Komentarze w kodzie: polski
- Przy edycji PHP sprawdzaj SSRF, injection, CORS

## Deploy
- Frontend: git push → GitHub Pages automatycznie aktualizuje
- Backend: ręcznie wgraj email-scraper.php do domains/plonpol.pl/public_html/ przez DirectAdmin

## Kluczowe zmienne
- EMAIL_SCRAPER_URL = 'https://plonpol.pl/email-scraper.php'
- API key Google: wpisywany przez użytkownika (overlay na starcie)

## Struktura kodu index.html
1. CSS (linie ~10-590) — style, responsive mobile @media
2. HTML body (linie ~590-790) — sidebar, right panel, mapa, tabela, dashboardy
3. JavaScript (linie ~790+):
   - State + security helpers (esc, escAttr)
   - Google Maps init + search flow (startSearch → doSearch → searchPlaces → getPlaceDetails)
   - Filtry: isBlacklisted (gastro + company), passesQualityFilter, filtr miasta, filtr dzielnicy
   - Rendering: renderResults, addMarkers, renderAnalytics (Chart.js)
   - Email scraping: scrapeEmails (warunkowy, checkbox)
   - Export: exportExcel (SheetJS)

## Blacklisty
- BAD_TYPES — typy wykluczone dla gastronomii
- COMPANY_BAD_TYPES — typy wykluczone dla firm (~50 typów)
- BLACKLIST_NAMES — sieciówki gastronomiczne
- COMPANY_BLACKLIST_NAMES — sieciowe banki, hotele, piekarnie
EOF