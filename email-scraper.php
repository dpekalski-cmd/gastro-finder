<?php
/**
 * Gastro Finder — Email Scraper v5 (security hardened)
 *
 * GET /email-scraper.php?url=https://example.com
 *
 * ── Zmiany względem v4 ──
 *  [SEC] Przekierowania obsługiwane RĘCZNIE — każdy hop przechodzi kontrolę SSRF.
 *        (v4: max_redirects=5 w stream wrapperze omijało całą walidację —
 *         evil.com → 302 → http://127.0.0.1/ przechodziło bez sprawdzenia)
 *  [SEC] Sprawdzamy WSZYSTKIE rekordy A i AAAA, nie tylko pierwszy adres IPv4.
 *        (v4: gethostbyname() nie widziało ::1 ani fd00::/8)
 *  [SEC] Fail-closed przy błędzie DNS (v4 przepuszczało niewiadome hosty).
 *  [SEC] Whitelist portów 80/443 (v4 pozwalało na skanowanie portów: host:22).
 *  [SEC] Walidacja IP hosta MX przed połączeniem SMTP (MX mógł wskazać localhost).
 *  [SEC] Weryfikacja certyfikatu TLS z awaryjnym fallbackiem przy braku CA bundle.
 *  [SEC] Rate limiting z flock() — brak wyścigu przy równoległych żądaniach.
 *  [PERF] Budżet czasu na całe żądanie — odpowiedź zawsze przed timeoutem frontendu.
 *  [PERF] Zgadywanie emaili: jedno połączenie SMTP na wiele RCPT TO
 *         (v4: osobny handshake na każdy z 15 prefiksów = do 75 s).
 *  [FIX] rawurldecode zamiast urldecode — urldecode zamieniał "+" na spację
 *        i psuł adresy typu jan+kontakt@domena.pl
 */

// Jakikolwiek warning/deprecation wypisany na wyjście psuje JSON i frontend
// wywala się na resp.json() — cała odpowiedź przepada. Logujemy, nie drukujemy.
@ini_set('display_errors', '0');
@ini_set('log_errors', '1');

// ── Budżet czasu ──
// Frontend przerywa po 15 s — musimy zdążyć odpowiedzieć wcześniej.
define('MAX_TOTAL_SECONDS', 12);
$START_TIME = microtime(true);
function timeLeft() {
    global $START_TIME;
    return MAX_TOTAL_SECONDS - (microtime(true) - $START_TIME);
}

define('SCRAPER_UA', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');

// ── CORS (strict) ──
$allowed_origins = [
    'https://dpekalski-cmd.github.io',
    'https://plonpol.pl',
    'https://www.plonpol.pl',
];
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
if (in_array($origin, $allowed_origins, true)) {
    header('Access-Control-Allow-Origin: ' . $origin);
    header('Vary: Origin');
}
// Brak nagłówka Origin = bezpośrednie wejście z przeglądarki — pozwalamy, ale bez CORS.
header('Access-Control-Allow-Methods: GET, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');
header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { http_response_code(204); exit; }

function fail($msg, $code = 200) {
    http_response_code($code);
    die(json_encode(['status' => 'error', 'message' => $msg, 'emails' => []], JSON_UNESCAPED_UNICODE));
}

if ($_SERVER['REQUEST_METHOD'] !== 'GET') fail('Tylko GET', 405);

$url = isset($_GET['url']) ? trim($_GET['url']) : '';
if ($url === '' || strlen($url) > 2000 || !preg_match('#^https?://#i', $url)) {
    fail('Nieprawidłowy URL');
}

// ═══════════════════════════════════════════
// ── SSRF: rozwiązywanie i klasyfikacja IP ──
// ═══════════════════════════════════════════

/** Zwraca WSZYSTKIE adresy (A + AAAA) hosta. Pusta tablica = nie udało się rozwiązać. */
function resolveHostIps($host) {
    if (filter_var($host, FILTER_VALIDATE_IP)) return [$host];

    $ips = [];
    if (function_exists('dns_get_record')) {
        $a = @dns_get_record($host, DNS_A);
        if (is_array($a)) foreach ($a as $r) { if (!empty($r['ip'])) $ips[] = $r['ip']; }
        $aaaa = @dns_get_record($host, DNS_AAAA);
        if (is_array($aaaa)) foreach ($aaaa as $r) { if (!empty($r['ipv6'])) $ips[] = $r['ipv6']; }
    }
    if (!$ips) {
        // Fallback gdy dns_get_record jest wyłączone na hostingu (tylko IPv4)
        $ip = @gethostbyname($host);
        if ($ip && $ip !== $host && filter_var($ip, FILTER_VALIDATE_IP)) $ips[] = $ip;
    }
    return array_values(array_unique($ips));
}

/** true = adres wewnętrzny/zarezerwowany, nie wolno się z nim łączyć. */
function isBlockedIp($ip) {
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        $long = ip2long($ip);
        if ($long === false) return true;
        $val = (float) sprintf('%u', $long);
        $ranges = [
            ['0.0.0.0',        '0.255.255.255'],     // "this network"
            ['10.0.0.0',       '10.255.255.255'],    // prywatne
            ['100.64.0.0',     '100.127.255.255'],   // CGNAT
            ['127.0.0.0',      '127.255.255.255'],   // loopback
            ['169.254.0.0',    '169.254.255.255'],   // link-local / metadata AWS
            ['172.16.0.0',     '172.31.255.255'],    // prywatne
            ['192.0.0.0',      '192.0.0.255'],       // IETF protocol assignments
            ['192.0.2.0',      '192.0.2.255'],       // TEST-NET-1
            ['192.168.0.0',    '192.168.255.255'],   // prywatne
            ['198.18.0.0',     '198.19.255.255'],    // benchmark
            ['198.51.100.0',   '198.51.100.255'],    // TEST-NET-2
            ['203.0.113.0',    '203.0.113.255'],     // TEST-NET-3
            ['224.0.0.0',      '255.255.255.255'],   // multicast + reserved + broadcast
        ];
        foreach ($ranges as [$start, $end]) {
            $s = (float) sprintf('%u', ip2long($start));
            $e = (float) sprintf('%u', ip2long($end));
            if ($val >= $s && $val <= $e) return true;
        }
        return false;
    }

    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
        $bin = @inet_pton($ip);
        if ($bin === false) return true;
        // IPv4-mapped (::ffff:127.0.0.1) — sprawdź jako IPv4
        if (substr($bin, 0, 12) === "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff") {
            return isBlockedIp(inet_ntop(substr($bin, 12)));
        }
        // Odrzuć wszystko, co nie jest globalnym unicastem
        if (!filter_var($ip, FILTER_VALIDATE_IP,
                FILTER_FLAG_IPV6 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
            return true;
        }
        return false;
    }

    return true; // nierozpoznany format — blokuj
}

/** null = URL wolno pobrać, string = powód odrzucenia. */
function validateFetchUrl($url) {
    $p = @parse_url($url);
    if (!$p || empty($p['host'])) return 'Nieprawidłowy URL';

    $scheme = strtolower($p['scheme'] ?? '');
    if (!in_array($scheme, ['http', 'https'], true)) return 'Niedozwolony protokół';

    $port = (int) ($p['port'] ?? ($scheme === 'https' ? 443 : 80));
    if (!in_array($port, [80, 443], true)) return 'Niedozwolony port';

    $host = strtolower(rtrim($p['host'], '.'));
    if ($host === '') return 'Nieprawidłowy host';
    if (in_array($host, ['localhost', 'metadata.google.internal', 'metadata'], true)) return 'Niedozwolony host';
    if (preg_match('/\.(local|internal|lan|localhost|test|invalid|onion|home|corp)$/i', $host)) return 'Niedozwolony host';

    $ips = resolveHostIps($host);
    if (!$ips) return 'Nie można rozwiązać domeny';   // fail-closed
    foreach ($ips as $ip) {
        if (isBlockedIp($ip)) return 'Adres wewnętrzny — zablokowany';
    }
    return null;
}

// ═══════════════════════════════════════════
// ── Rate limiting (500/h, z blokadą pliku) ──
// Przed walidacją URL — validateFetchUrl() robi odpytania DNS, więc bez limitu
// endpoint dałoby się wykorzystać jako darmowy resolver/amplifikator.
// ═══════════════════════════════════════════
$rate_dir = sys_get_temp_dir() . '/gastro_rl';
if (!is_dir($rate_dir)) @mkdir($rate_dir, 0700, true);
$rf = $rate_dir . '/' . md5($_SERVER['REMOTE_ADDR'] ?? '?');
$fh = @fopen($rf, 'c+');
if ($fh) {
    if (@flock($fh, LOCK_EX)) {
        $raw = stream_get_contents($fh);
        $d   = $raw ? json_decode($raw, true) : null;
        $count = 0;
        $since = time();
        if (is_array($d) && (time() - ($d['s'] ?? 0)) < 3600) {
            $count = (int) ($d['c'] ?? 0);
            $since = (int) $d['s'];
        }
        if ($count >= 500) {
            @flock($fh, LOCK_UN);
            @fclose($fh);
            fail('Rate limit', 429);
        }
        ftruncate($fh, 0);
        rewind($fh);
        fwrite($fh, json_encode(['c' => $count + 1, 's' => $since]));
        fflush($fh);
        @flock($fh, LOCK_UN);
    }
    @fclose($fh);
}

// ── Walidacja adresu wejściowego (SSRF) ──
$reason = validateFetchUrl($url);
if ($reason !== null) fail($reason);

// ═══════════════════════════════════════════
// ── Rozpoznanie typu URL ──
// ═══════════════════════════════════════════
$parsed = parse_url($url);
$host   = strtolower($parsed['host'] ?? '');

$skip_always = ['instagram.com','tiktok.com','youtube.com','twitter.com','x.com',
                'linkedin.com','booking.com','tripadvisor.com','yelp.com','pyszne.pl',
                'glovo.com','zomato.com','wolt.com','ubereats.com','goo.gl',
                'sites.google.com'];
foreach ($skip_always as $s) {
    if (strpos($host, $s) !== false) {
        die(json_encode(['status'=>'skipped','message'=>'Portal bez emaili','url'=>$url,'emails'=>[]], JSON_UNESCAPED_UNICODE));
    }
}

$isFacebook = (strpos($host, 'facebook.com') !== false || strpos($host, 'fb.com') !== false);

// ═══════════════════════════════════════════
// ── Pobieranie stron (cURL, ręczne redirecty) ──
// ═══════════════════════════════════════════

/** Jedno żądanie HTTP bez podążania za przekierowaniem. Zwraca [body, status, location]. */
function httpGetOnce($url) {
    $maxSize = 2 * 1024 * 1024; // 2 MB
    $budget  = (int) max(3, min(8, floor(timeLeft())));

    if (function_exists('curl_init')) {
        $ch = curl_init($url);
        $opts = [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => false,   // redirecty obsługujemy sami (SSRF)
            CURLOPT_HEADER         => false,
            CURLOPT_TIMEOUT        => $budget,
            CURLOPT_CONNECTTIMEOUT => 4,
            CURLOPT_USERAGENT      => SCRAPER_UA,
            CURLOPT_HTTPHEADER     => [
                'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language: pl-PL,pl;q=0.9,en;q=0.8',
            ],
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_MAXFILESIZE    => $maxSize,
            CURLOPT_NOPROGRESS     => false,
            CURLOPT_PROGRESSFUNCTION => function ($res, $dlTotal, $dlNow, $ulTotal, $ulNow) use ($maxSize) {
                return ($dlNow > $maxSize) ? 1 : 0; // przerwij transfer po przekroczeniu limitu
            },
        ];
        // CURLOPT_PROTOCOLS jest deprecated od PHP 8.4 (notice psułby JSON) —
        // na nowszych wersjach używamy wariantu _STR
        if (defined('CURLOPT_PROTOCOLS_STR')) {
            $opts[CURLOPT_PROTOCOLS_STR] = 'http,https';
        } elseif (defined('CURLOPT_PROTOCOLS')) {
            $opts[CURLOPT_PROTOCOLS] = CURLPROTO_HTTP | CURLPROTO_HTTPS;
        }
        curl_setopt_array($ch, $opts);

        $body = curl_exec($ch);
        // Brak/przeterminowany CA bundle na hostingu współdzielonym — ponów bez weryfikacji.
        // Scrapujemy publiczne strony, więc utrata poufności nie jest tu istotna,
        // ale próbujemy zweryfikowanego połączenia jako pierwszego wyboru.
        if ($body === false && in_array(curl_errno($ch), [51, 58, 60, 77, 83], true)) {
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
            $body = curl_exec($ch);
        }
        $status   = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $location = curl_getinfo($ch, CURLINFO_REDIRECT_URL) ?: '';
        curl_close($ch);

        if ($body === false) return [false, $status, ''];
        return [substr($body, 0, $maxSize), $status, $location];
    }

    // ── Fallback: stream wrapper, max_redirects=1 oznacza "nie podążaj" ──
    $ctx = stream_context_create([
        'http' => [
            'timeout'       => $budget,
            'max_redirects' => 1,
            'header'        => implode("\r\n", [
                'User-Agent: ' . SCRAPER_UA,
                'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language: pl-PL,pl;q=0.9,en;q=0.8',
            ]),
            'ignore_errors' => true,
        ],
        'ssl' => ['verify_peer' => false, 'verify_peer_name' => false],
    ]);
    $fp = @fopen($url, 'r', false, $ctx);
    if (!$fp) return [false, 0, ''];

    $status = 0;
    $location = '';
    foreach (($http_response_header ?? []) as $h) {
        if (preg_match('#^HTTP/\S+\s+(\d{3})#', $h, $m)) $status = (int) $m[1];
        if (stripos($h, 'Location:') === 0) $location = trim(substr($h, 9));
    }

    $data = '';
    while (!feof($fp) && strlen($data) < $maxSize) {
        $chunk = fread($fp, 8192);
        if ($chunk === false) break;
        $data .= $chunk;
    }
    fclose($fp);

    return [$data !== '' ? $data : false, $status, $location];
}

/** Zamienia względny Location na absolutny URL. */
function absolutizeUrl($base, $location) {
    if (preg_match('#^https?://#i', $location)) return $location;
    $p = @parse_url($base);
    if (!$p || empty($p['host'])) return null;
    $root = ($p['scheme'] ?? 'http') . '://' . $p['host'];
    if (strpos($location, '/') === 0) return $root . $location;
    $path = $p['path'] ?? '/';
    $dir  = substr($path, 0, strrpos($path, '/') + 1);
    return $root . ($dir ?: '/') . $location;
}

/** Pobiera stronę, walidując SSRF na KAŻDYM przekierowaniu. */
function fetchPage($url, $maxRedirects = 3) {
    $hops = 0;
    while (true) {
        if (timeLeft() < 3) return false;
        if (validateFetchUrl($url) !== null) return false;

        [$body, $status, $location] = httpGetOnce($url);

        if (in_array($status, [301, 302, 303, 307, 308], true) && $location !== '') {
            if (++$hops > $maxRedirects) return false;
            $next = absolutizeUrl($url, $location);
            if (!$next) return false;
            $url = $next;
            continue;   // pętla ponownie waliduje nowy adres
        }
        return $body;
    }
}

// ═══════════════════════════════════════════
// ── Wyciąganie emaili ──
// ═══════════════════════════════════════════
function extractEmails($html) {
    if (!$html) return [];
    $text = html_entity_decode($html, ENT_QUOTES, 'UTF-8');
    // rawurldecode, nie urldecode — urldecode zamienia "+" na spację i psuje adresy
    $text = rawurldecode($text);
    $text = preg_replace('/\s*[\[\(]\s*at\s*[\]\)]\s*/i', '@', $text);
    $text = preg_replace('/\s*[\[\(]\s*dot\s*[\]\)]\s*/i', '.', $text);

    preg_match_all('/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/', $text, $matches);
    $emails = array_unique($matches[0]);

    // W tekście zakodowanym w URL-u "+" stoi w miejscu spacji, np.
    // "napisz+na+adres+dialog@uczelnia.pl" — regex zabiera całość razem ze słowami.
    // Reguła: jeśli część lokalna ZACZYNA się od "+", to na pewno doklejony tekst,
    // więc obcinamy do ostatniego "+". Prawdziwe plus-adresowanie ("jan+sklep@x.pl")
    // nigdy nie zaczyna się od "+", więc zostaje nietknięte.
    $emails = array_map(function ($e) {
        if ($e === '' || $e[0] !== '+') return $e;
        $at = strpos($e, '@');
        if ($at === false) return $e;
        $local = substr($e, 0, $at);
        $cut   = strrpos($local, '+');
        $local = ($cut === false) ? $local : substr($local, $cut + 1);
        return $local === '' ? '' : $local . substr($e, $at);
    }, $emails);
    $emails = array_unique(array_filter($emails));

    $blacklist = [
        '/\.(png|jpg|jpeg|gif|svg|webp|css|js|woff|woff2|ttf|eot|ico)$/i',
        '/wixpress|wixsite|sentry\.io|webpack|cloudflare|googleapis|fbcdn/i',
        '/example\.com|domain\.com|email\.com|yourmail|test@|noreply|no-reply/i',
        '/wordpress|developer|schema\.org|ogp\.me|w3\.org|gravatar/i',
        '/@[0-9]+\./i',
        '/protection@|abuse@|postmaster@|hostmaster@|webmaster@/i',
        '/support@(wordpress|squarespace|wix|weebly)/i',
    ];
    $emails = array_filter($emails, function ($e) use ($blacklist) {
        if (strlen($e) > 60 || strlen($e) < 6) return false;
        foreach ($blacklist as $p) { if (preg_match($p, $e)) return false; }
        return true;
    });
    return array_values(array_map('trim', $emails));
}

// ── Wyciągnij domenę biznesową z URL ──
function extractBusinessDomain($url, $html = '') {
    $parsed = parse_url($url);
    $host   = strtolower($parsed['host'] ?? '');

    $social = ['facebook.com','fb.com','instagram.com','twitter.com','x.com',
               'tiktok.com','youtube.com','linkedin.com','google.com'];
    $isSocial = false;
    foreach ($social as $s) {
        if (strpos($host, $s) !== false) { $isSocial = true; break; }
    }

    if (!$isSocial) return preg_replace('/^www\./', '', $host);

    if ($html) {
        preg_match_all('#https?://[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}#', $html, $urlMatches);
        foreach ($urlMatches[0] as $foundUrl) {
            $fHost = strtolower(parse_url($foundUrl, PHP_URL_HOST) ?? '');
            $fHost = preg_replace('/^www\./', '', $fHost);
            $isS = false;
            foreach ($social as $s) { if (strpos($fHost, $s) !== false) { $isS = true; break; } }
            if (!$isS && !preg_match('/(cdn|pixel|analytics|tracking|gstatic|fbcdn)/i', $fHost)) {
                if (strlen($fHost) > 3 && strpos($fHost, '.') !== false) return $fHost;
            }
        }
    }
    return null;
}

// ═══════════════════════════════════════════
// ── Zgadywanie emaili (jedno połączenie SMTP) ──
// ═══════════════════════════════════════════
function guessEmails($domain) {
    if (!$domain || strlen($domain) > 100) return [];
    if (!preg_match('/^[a-zA-Z0-9.\-]+$/', $domain)) return [];
    if (!function_exists('getmxrr')) return [];
    if (timeLeft() < 6) return [];

    $mxHosts = [];
    if (!@getmxrr($domain, $mxHosts) || !$mxHosts) return [];
    $mxHost = $mxHosts[0];

    // SSRF: rekord MX też może wskazywać na adres wewnętrzny
    $mxIps = resolveHostIps($mxHost);
    if (!$mxIps) return [];
    foreach ($mxIps as $ip) { if (isBlockedIp($ip)) return []; }

    $prefixes = [
        'kontakt', 'info', 'biuro', 'rezerwacja', 'rezerwacje',
        'hello', 'hej', 'restauracja', 'kawiarnia', 'cafe',
        'bar', 'bistro', 'office', 'mail', 'admin',
    ];

    $errno = 0; $errstr = '';
    $sock = @fsockopen($mxHost, 25, $errno, $errstr, 4);
    if (!$sock) return [];
    stream_set_timeout($sock, 4);

    $found = [];
    try {
        $resp = @fgets($sock, 1024);
        if (!$resp || substr($resp, 0, 3) !== '220') return [];

        @fwrite($sock, "HELO gastrofinder.local\r\n");
        @fgets($sock, 1024);
        @fwrite($sock, "MAIL FROM:<verify@gastrofinder.local>\r\n");
        @fgets($sock, 1024);

        // Jedna sesja, wiele RCPT TO — v4 otwierało nowe połączenie na każdy prefiks
        foreach ($prefixes as $prefix) {
            if (timeLeft() < 2) break;
            $email = $prefix . '@' . $domain;
            if (!filter_var($email, FILTER_VALIDATE_EMAIL)) continue;
            if (preg_match('/[\r\n]/', $email)) continue;   // SMTP injection

            @fwrite($sock, "RCPT TO:<" . $email . ">\r\n");
            $resp = @fgets($sock, 1024);
            if ($resp === false) break;                     // serwer zerwał połączenie
            if (substr($resp, 0, 3) === '250') { $found[] = $email; break; }
        }
        @fwrite($sock, "QUIT\r\n");
    } finally {
        @fclose($sock);
    }

    return $found;
}

// ═══════════════════════════════════════════
// ── GŁÓWNA LOGIKA ──
// ═══════════════════════════════════════════
$allEmails    = [];
$pagesChecked = 0;
$method       = '';

if ($isFacebook) {
    $fbUrl = preg_replace('/\?.*$/', '', $url);
    $fbUrl = preg_replace('/(\/posts|\/photos|\/videos|\/story\.php|\/reviews|\/events).*$/i', '', $fbUrl);
    $fbUrl = rtrim($fbUrl, '/');

    $lastHtml = '';
    foreach ([$fbUrl . '/about', $fbUrl] as $pageUrl) {
        if (timeLeft() < 3) break;
        $html = fetchPage($pageUrl);
        $pagesChecked++;
        if ($html) {
            $lastHtml = $html;
            $found = extractEmails($html);
            $allEmails = array_merge($allEmails, $found);
            if ($found) { $method = 'facebook'; break; }
        }
    }

    if (!$allEmails && $lastHtml !== '') {
        $bizDomain = extractBusinessDomain($url, $lastHtml);
        if ($bizDomain) {
            $guessed = guessEmails($bizDomain);
            $allEmails = array_merge($allEmails, $guessed);
            if ($guessed) $method = 'guessed_from_fb';
        }
    }
} else {
    $scheme  = $parsed['scheme'] ?? 'https';
    $baseUrl = $scheme . '://' . $parsed['host'] . (isset($parsed['port']) ? ':' . (int) $parsed['port'] : '');

    $html = fetchPage($url);
    $pagesChecked++;
    if ($html) {
        $allEmails = extractEmails($html);
        if ($allEmails) $method = 'homepage';

        if (!$allEmails) {
            $contactPaths    = [];
            $contactKeywords = ['kontakt', 'contact', 'o-nas', 'about', 'about-us', 'dane-kontaktowe', 'napisz'];

            preg_match_all('/href=["\']([^"\']{3,120})["\']/', $html, $linkMatches);
            foreach ($linkMatches[1] as $link) {
                $linkLower = strtolower($link);
                if (preg_match('#^(\#|javascript:|mailto:|tel:|data:)#i', $link)) continue;
                foreach ($contactKeywords as $kw) {
                    if (strpos($linkLower, $kw) === false) continue;
                    if (preg_match('#^https?://#i', $link)) {
                        $lh = strtolower(parse_url($link, PHP_URL_HOST) ?? '');
                        $bh = strtolower($parsed['host']);
                        // ten sam host albo jego subdomena — nie wychodzimy na obce domeny.
                        // v4 używało strpos(), więc "example.com.evil.pl" przechodziło.
                        $sameSite = ($lh !== '') && (
                            $lh === $bh ||
                            substr($lh, -strlen('.' . $bh)) === '.' . $bh ||
                            substr($bh, -strlen('.' . $lh)) === '.' . $lh
                        );
                        if ($sameSite) $contactPaths[] = $link;
                    } elseif (strpos($link, '/') === 0) {
                        $contactPaths[] = $baseUrl . $link;
                    } else {
                        $contactPaths[] = $baseUrl . '/' . $link;
                    }
                    break;
                }
            }

            if (!$contactPaths) {
                foreach (['/kontakt','/contact','/kontakt/','/contact/','/o-nas','/about'] as $g) {
                    $contactPaths[] = $baseUrl . $g;
                }
            }

            $contactPaths = array_slice(array_values(array_unique($contactPaths)), 0, 3);

            foreach ($contactPaths as $cp) {
                if (timeLeft() < 3) break;
                $subHtml = fetchPage($cp);
                $pagesChecked++;
                if ($subHtml) {
                    $found = extractEmails($subHtml);
                    $allEmails = array_merge($allEmails, $found);
                    if ($found) { $method = 'subpage'; break; }
                }
            }
        }
    }

    if (!$allEmails) {
        $bizDomain = extractBusinessDomain($url);
        if ($bizDomain) {
            $guessed = guessEmails($bizDomain);
            $allEmails = array_merge($allEmails, $guessed);
            if ($guessed) $method = 'guessed';
        }
    }
}

$allEmails = array_values(array_unique(array_map('strtolower', $allEmails)));

echo json_encode([
    'status'        => 'ok',
    'url'           => $url,
    'emails'        => $allEmails,
    'method'        => $method ?: 'none',
    'pages_checked' => $pagesChecked,
], JSON_UNESCAPED_UNICODE);
