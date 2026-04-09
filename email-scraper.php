<?php
/**
 * Gastro Finder — Email Scraper v4 (security hardened)
 * 
 * GET /email-scraper.php?url=https://example.com
 */

// ── CORS (strict) ──
$allowed_origins = [
    'https://dpekalski-cmd.github.io',
    'https://plonpol.pl',
    'https://www.plonpol.pl',
];
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
if (in_array($origin, $allowed_origins, true)) {
    header('Access-Control-Allow-Origin: ' . $origin);
} elseif (empty($origin)) {
    // Bezpośredni dostęp z przeglądarki (bez Origin) — pozwalamy ale bez CORS
    // Frontend z innej domeny nie będzie mógł odczytać odpowiedzi
}
header('Access-Control-Allow-Methods: GET, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');
header('Content-Type: application/json; charset=utf-8');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { http_response_code(204); exit; }
if ($_SERVER['REQUEST_METHOD'] !== 'GET') { die(json_encode(['status'=>'error','message'=>'Tylko GET','emails'=>[]])); }

$url = isset($_GET['url']) ? trim($_GET['url']) : '';
if (empty($url) || !preg_match('/^https?:\/\//i', $url)) {
    die(json_encode(['status'=>'error','message'=>'Nieprawidłowy URL','emails'=>[]]));
}

// ── SSRF Protection: blokuj adresy prywatne/lokalne ──
function isPrivateUrl($url) {
    $parsed = parse_url($url);
    $host = strtolower($parsed['host'] ?? '');
    
    // Blokuj oczywiste lokalne hosty
    $blocked = ['localhost', '127.0.0.1', '0.0.0.0', '::1', 'metadata.google.internal'];
    if (in_array($host, $blocked, true)) return true;
    
    // Blokuj domeny .local, .internal, .lan
    if (preg_match('/\.(local|internal|lan|test|invalid|onion)$/i', $host)) return true;
    
    // Rozwiąż DNS i sprawdź czy IP jest prywatne
    $ip = gethostbyname($host);
    if ($ip === $host) return false; // nie udało się rozwiązać — pozwól (może zadziała)
    
    $privateRanges = [
        ['10.0.0.0', '10.255.255.255'],
        ['172.16.0.0', '172.31.255.255'],
        ['192.168.0.0', '192.168.255.255'],
        ['127.0.0.0', '127.255.255.255'],
        ['169.254.0.0', '169.254.255.255'], // link-local / AWS metadata
        ['100.64.0.0', '100.127.255.255'],  // CGNAT
    ];
    $ipLong = ip2long($ip);
    if ($ipLong === false) return false;
    foreach ($privateRanges as [$start, $end]) {
        if ($ipLong >= ip2long($start) && $ipLong <= ip2long($end)) return true;
    }
    return false;
}

if (isPrivateUrl($url)) {
    die(json_encode(['status'=>'error','message'=>'Niedozwolony adres','emails'=>[]]));
}

// ── Rate limiting (500/h) ──
$rate_dir = sys_get_temp_dir() . '/gastro_rl';
if (!is_dir($rate_dir)) @mkdir($rate_dir, 0755, true);
$rf = $rate_dir . '/' . md5($_SERVER['REMOTE_ADDR'] ?? '?');
$rc = 0; $rs = time();
if (file_exists($rf)) {
    $d = json_decode(file_get_contents($rf), true);
    if ($d && (time() - ($d['s'] ?? 0)) < 3600) { $rc = $d['c'] ?? 0; $rs = $d['s']; }
}
if ($rc >= 500) { http_response_code(429); die(json_encode(['status'=>'error','message'=>'Rate limit','emails'=>[]])); }
file_put_contents($rf, json_encode(['c' => $rc + 1, 's' => $rs]));

// ── Rozpoznaj typ URL ──
$parsed = parse_url($url);
$host = strtolower($parsed['host'] ?? '');

$skip_always = ['instagram.com','tiktok.com','youtube.com','twitter.com','x.com',
                'linkedin.com','booking.com','tripadvisor.com','yelp.com','pyszne.pl',
                'glovo.com','zomato.com','wolt.com','ubereats.com','goo.gl',
                'sites.google.com'];
foreach ($skip_always as $s) {
    if (strpos($host, $s) !== false) {
        die(json_encode(['status'=>'skipped','message'=>'Portal bez emaili','url'=>$url,'emails'=>[]]));
    }
}

$isFacebook = (strpos($host, 'facebook.com') !== false || strpos($host, 'fb.com') !== false);

// ── Funkcja pobierania strony (z limitem rozmiaru) ──
function fetchPage($url) {
    // Dodatkowy SSRF check na podstronach
    if (isPrivateUrl($url)) return false;
    
    $maxSize = 2 * 1024 * 1024; // 2MB max
    $ctx = stream_context_create([
        'http' => [
            'timeout' => 10,
            'max_redirects' => 5,
            'header' => implode("\r\n", [
                "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language: pl-PL,pl;q=0.9,en;q=0.8",
            ]),
            'ignore_errors' => true,
        ],
        'ssl' => ['verify_peer' => false, 'verify_peer_name' => false],
    ]);
    
    $fp = @fopen($url, 'r', false, $ctx);
    if (!$fp) return false;
    
    $data = '';
    while (!feof($fp) && strlen($data) < $maxSize) {
        $chunk = fread($fp, 8192);
        if ($chunk === false) break;
        $data .= $chunk;
    }
    fclose($fp);
    
    return $data ?: false;
}

// ── Funkcja wyciągania emaili z HTML ──
function extractEmails($html) {
    if (!$html) return [];
    $text = html_entity_decode($html, ENT_QUOTES, 'UTF-8');
    $text = urldecode($text);
    $text = preg_replace('/\s*\[\s*at\s*\]\s*/i', '@', $text);
    $text = preg_replace('/\s*\(\s*at\s*\)\s*/i', '@', $text);
    $text = preg_replace('/\s*\[dot\]\s*/i', '.', $text);
    $text = preg_replace('/\s*\(dot\)\s*/i', '.', $text);

    preg_match_all('/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/', $text, $matches);
    $emails = array_unique($matches[0]);

    $blacklist = [
        '/\.(png|jpg|jpeg|gif|svg|webp|css|js|woff|woff2|ttf|eot|ico)$/i',
        '/wixpress|wixsite|sentry\.io|webpack|cloudflare|googleapis|fbcdn/i',
        '/example\.com|domain\.com|email\.com|yourmail|test@|noreply|no-reply/i',
        '/wordpress|developer|schema\.org|ogp\.me|w3\.org|gravatar/i',
        '/@[0-9]+\./i',
        '/protection@|abuse@|postmaster@|hostmaster@|webmaster@/i',
        '/support@(wordpress|squarespace|wix|weebly)/i',
    ];
    $emails = array_filter($emails, function($e) use ($blacklist) {
        if (strlen($e) > 60 || strlen($e) < 6) return false;
        foreach ($blacklist as $p) { if (preg_match($p, $e)) return false; }
        return true;
    });
    return array_values(array_map('trim', $emails));
}

// ── Wyciągnij domenę biznesową z URL ──
function extractBusinessDomain($url, $html = '') {
    $parsed = parse_url($url);
    $host = strtolower($parsed['host'] ?? '');
    
    $social = ['facebook.com','fb.com','instagram.com','twitter.com','x.com',
               'tiktok.com','youtube.com','linkedin.com','google.com'];
    $isSocial = false;
    foreach ($social as $s) {
        if (strpos($host, $s) !== false) { $isSocial = true; break; }
    }
    
    if (!$isSocial) {
        return preg_replace('/^www\./', '', $host);
    }
    
    if ($html) {
        preg_match_all('/https?:\/\/[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/', $html, $urlMatches);
        foreach ($urlMatches[0] as $foundUrl) {
            $fHost = strtolower(parse_url($foundUrl, PHP_URL_HOST) ?? '');
            $fHost = preg_replace('/^www\./', '', $fHost);
            $isS = false;
            foreach ($social as $s) { if (strpos($fHost, $s) !== false) { $isS = true; break; } }
            if (!$isS && !preg_match('/(cdn|pixel|analytics|tracking|gstatic|fbcdn)/i', $fHost)) {
                if (strlen($fHost) > 3 && strpos($fHost, '.') !== false) {
                    return $fHost;
                }
            }
        }
    }
    return null;
}

// ── Zgadywanie emaili na domenie (DNS MX check) ──
function guessEmails($domain) {
    if (!$domain || strlen($domain) > 100) return [];
    // Sanitize domain — tylko litery, cyfry, kropki, myślniki
    if (!preg_match('/^[a-zA-Z0-9.\-]+$/', $domain)) return [];
    
    if (!checkdnsrr($domain, 'MX')) return [];
    
    $prefixes = [
        'kontakt', 'info', 'biuro', 'rezerwacja', 'rezerwacje',
        'hello', 'hej', 'restauracja', 'kawiarnia', 'cafe',
        'bar', 'bistro', 'office', 'mail', 'admin'
    ];
    
    $validEmails = [];
    foreach ($prefixes as $prefix) {
        $email = $prefix . '@' . $domain;
        if (verifyEmailSMTP($email, $domain)) {
            $validEmails[] = $email;
            break;
        }
    }
    return $validEmails;
}

// ── Weryfikacja email przez SMTP ──
function verifyEmailSMTP($email, $domain) {
    // Sanitize email — nie pozwól na znaki specjalne SMTP
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) return false;
    if (preg_match('/[\r\n]/', $email)) return false; // SMTP injection prevention
    
    $mxHosts = [];
    if (!getmxrr($domain, $mxHosts)) return false;
    
    $mxHost = $mxHosts[0] ?? $domain;
    
    $errno = 0;
    $errstr = '';
    $sock = @fsockopen($mxHost, 25, $errno, $errstr, 5);
    if (!$sock) return false;
    
    stream_set_timeout($sock, 5);
    
    $response = @fgets($sock, 1024);
    if (!$response || strpos($response, '220') === false) { @fclose($sock); return false; }
    
    @fwrite($sock, "HELO gastrofinder.local\r\n");
    $response = @fgets($sock, 1024);
    
    @fwrite($sock, "MAIL FROM:<verify@gastrofinder.local>\r\n");
    $response = @fgets($sock, 1024);
    
    @fwrite($sock, "RCPT TO:<" . $email . ">\r\n");
    $response = @fgets($sock, 1024);
    
    @fwrite($sock, "QUIT\r\n");
    @fclose($sock);
    
    return ($response && strpos($response, '250') !== false);
}


// ═══════════════════════════════════════════
// ── GŁÓWNA LOGIKA ──
// ═══════════════════════════════════════════
$allEmails = [];
$pagesChecked = 0;
$method = '';

if ($isFacebook) {
    $fbUrl = preg_replace('/\?.*$/', '', $url);
    $fbUrl = preg_replace('/(\/posts|\/photos|\/videos|\/story\.php|\/reviews|\/events).*$/i', '', $fbUrl);
    $fbUrl = rtrim($fbUrl, '/');

    foreach ([$fbUrl . '/about', $fbUrl] as $pageUrl) {
        $html = fetchPage($pageUrl);
        $pagesChecked++;
        if ($html) {
            $found = extractEmails($html);
            $allEmails = array_merge($allEmails, $found);
            if (!empty($found)) { $method = 'facebook'; break; }
        }
    }
    
    if (empty($allEmails) && !empty($html)) {
        $bizDomain = extractBusinessDomain($url, $html);
        if ($bizDomain) {
            $guessed = guessEmails($bizDomain);
            $allEmails = array_merge($allEmails, $guessed);
            if (!empty($guessed)) $method = 'guessed_from_fb';
        }
    }
} else {
    $baseUrl = $parsed['scheme'] . '://' . $parsed['host'];
    
    $html = fetchPage($url);
    $pagesChecked++;
    if ($html) {
        $allEmails = extractEmails($html);
        if (!empty($allEmails)) $method = 'homepage';

        if (empty($allEmails)) {
            $contactPaths = [];
            $contactKeywords = ['kontakt', 'contact', 'o-nas', 'about', 'about-us', 'dane-kontaktowe', 'napisz'];
            
            preg_match_all('/href=["\']([^"\']{3,120})["\']/', $html, $linkMatches);
            foreach ($linkMatches[1] as $link) {
                $linkLower = strtolower($link);
                if (preg_match('/^(#|javascript:|mailto:|tel:|data:)/i', $link)) continue;
                foreach ($contactKeywords as $kw) {
                    if (strpos($linkLower, $kw) !== false) {
                        if (preg_match('/^https?:\/\//', $link)) {
                            $lh = parse_url($link, PHP_URL_HOST);
                            if ($lh && strpos(strtolower($lh), strtolower($parsed['host'])) !== false) {
                                $contactPaths[] = $link;
                            }
                        } elseif (strpos($link, '/') === 0) {
                            $contactPaths[] = $baseUrl . $link;
                        } else {
                            $contactPaths[] = $baseUrl . '/' . $link;
                        }
                        break;
                    }
                }
            }

            if (empty($contactPaths)) {
                foreach (['/kontakt','/contact','/kontakt/','/contact/','/o-nas','/about'] as $g) {
                    $contactPaths[] = $baseUrl . $g;
                }
            }

            $contactPaths = array_values(array_unique($contactPaths));
            $contactPaths = array_slice($contactPaths, 0, 3);

            foreach ($contactPaths as $cp) {
                $subHtml = fetchPage($cp);
                $pagesChecked++;
                if ($subHtml) {
                    $found = extractEmails($subHtml);
                    $allEmails = array_merge($allEmails, $found);
                    if (!empty($found)) { $method = 'subpage'; break; }
                }
            }
        }
    }

    if (empty($allEmails)) {
        $bizDomain = extractBusinessDomain($url);
        if ($bizDomain) {
            $guessed = guessEmails($bizDomain);
            $allEmails = array_merge($allEmails, $guessed);
            if (!empty($guessed)) $method = 'guessed';
        }
    }
}

$allEmails = array_values(array_unique(array_map('strtolower', $allEmails)));

echo json_encode([
    'status' => 'ok',
    'url' => $url,
    'emails' => $allEmails,
    'method' => $method ?: 'none',
    'pages_checked' => $pagesChecked,
], JSON_UNESCAPED_UNICODE);
