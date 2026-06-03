<?php

require_once(dirname(__DIR__) . '/AgentConfig.php');

/**
 * @file plugins/generic/securityAgent/collectors/ResponseCollector.php
 *
 * Monitor output HTML yang dirender OJS sebelum dikirim ke browser.
 * Fokus pada content hash dari bagian yang stabil — bukan hash seluruh HTML
 * agar tidak false positive akibat dynamic content (view count, tanggal, dll).
 */
class ResponseCollector
{
    /** @var ResultSender */
    private $_sender;

    /**
     * Selector CSS untuk bagian HTML yang dianggap "stabil"
     * — bagian ini yang di-hash, bukan seluruh halaman.
     * Tambah/kurangi sesuai kebutuhan.
     */
    private $_stableSelectors = [
        'article.article-summary',
        'div.article-full-text',
        'div.pkp_structure_main',
        'nav.pkp_navigation_primary',
        'div.submission_metadata',
    ];

    private $_scanPatterns = [
        // ── XSS patterns ────────────────────────────────────────────
        [
            '/on(?:load|error|click|mouseover|focus|blur|change|submit)\s*=\s*["\']?(?!return\s+false)[^"\'>\s]/i',
            'high',
            'Inline event handler mencurigakan ditemukan di HTML output',
        ],
        [
            '/javascript\s*:/i',
            'high',
            'javascript: URI ditemukan — potensi XSS',
        ],
        [
            '/<script[^>]*>(?!.*(?:pkp|jquery|bootstrap|app\.js|main\.js))[^<]{10,}/i',
            'high',
            'Inline script mencurigakan ditemukan di HTML output',
        ],
        [
            '/document\s*\.\s*(?:write|cookie|location)\s*\(/i',
            'high',
            'DOM manipulation berbahaya ditemukan di HTML',
        ],
        [
            '/eval\s*\(/i',
            'critical',
            'eval() ditemukan di HTML output — potensi RCE/XSS',
        ],
        [
            '/base64_decode\s*\(/i',
            'critical',
            'base64_decode() ditemukan di HTML output — potensi code injection',
        ],
 
        // ── External resource injection ──────────────────────────────
        [
            '/<script[^>]+src=["\']https?:\/\/(?!(?:cdn\.jsdelivr\.net|cdnjs\.cloudflare\.com|ajax\.googleapis\.com|code\.jquery\.com))[^"\']+["\'][^>]*>/i',
            'medium',
            'External script dari domain tidak dikenal ditemukan',
        ],
        [
            '/<iframe[^>]+src=["\']https?:\/\/[^"\']+["\'][^>]*>/i',
            'medium',
            'External iframe ditemukan — potensi clickjacking atau konten berbahaya',
        ],
        [
            '/<form[^>]+action=["\']https?:\/\/(?!localhost)[^"\']+["\'][^>]*>/i',
            'high',
            'Form action mengarah ke domain eksternal — potensi phishing',
        ],
        [
            '/<meta[^>]+http-equiv=["\']refresh["\'][^>]+content=["\'][^"\']*url=https?:\/\/[^"\']+["\'][^>]*>/i',
            'high',
            'Meta refresh redirect ke URL eksternal ditemukan',
        ],
 
        // ── Obfuscation patterns ─────────────────────────────────────
        [
            '/(?:String\.fromCharCode|unescape|decodeURIComponent)\s*\([^)]{20,}\)/i',
            'medium',
            'Obfuscated string ditemukan di HTML output',
        ],
        [
            '/(?:\\\\x[0-9a-f]{2}){5,}/i',
            'medium',
            'Hex-encoded string mencurigakan ditemukan',
        ],
    ];

    public function __construct($sender)
    {
        $this->_sender = $sender;
    }

    // ── Hook Handlers ────────────────────────────────────────────────

    /**
     * Dipanggil sebelum template di-render ke browser.
     * Tangkap: template name, context, stable content hash.
     *
     * Hook: TemplateManager::display
     * Params: [&$templateMgr, &$template]
     */
    public function onTemplateDisplay($hookName, $params)
    {
        $templateMgr = $params[0] ?? null;
        $template    = $params[1] ?? '';

        if (!$templateMgr) return false;

        // Fetch output HTML tanpa kirim ke browser
        // OJS 3.3: templateMgr->fetch() render template ke string
        try {
            $html = $templateMgr->fetch($template);
        } catch (Exception $e) {
            return false;
        }

        $threats = [];
        if (in_array($pageType, $this->_scanPageTypes)) {
            $threats = $this->_scanRenderedHtml($html);
        }

        $stableHash = $this->_hashStableContent($html);
        $pageType   = $this->_detectPageType($template);

        $data = [
            'type'        => 'response_render',
            'template'    => $template,
            'page_type'   => $pageType,
            'url'         => $_SERVER['REQUEST_URI'] ?? '',
            'stable_hash' => $stableHash,
            'html_length' => strlen($html),
            'user_id'     => $this->_getCurrentUserId(),
            'ts'          => time(),
        ];

        if (empty($threats)) {
            $data['threats'] = $threats; // tetap kirim array kosong untuk konsistensi
            $data['threat_count'] = count($threats);

            $this->_sender->send(array_merge($data, [
                'type' => 'content_injection_alert',
            ]));
 
            error_log(sprintf(
                '[SecurityAgent][ResponseScan] %d threat(s) di %s',
                count($threats),
                $_SERVER['REQUEST_URI'] ?? ''
            ));
        }

        $this->_sender->send($data);
        return false;
    }

    /**
     * Hook ke AJAX response (grid, tab, modal OJS).
     * Tangkap: tipe handler dan context-nya.
     *
     * Hook: PKPHandler::setupTemplate
     * Params: [&$handler, &$request]
     */
    public function onSetupTemplate($hookName, $params)
    {
        $handler = $params[0] ?? null;
        $request = $params[1] ?? null;

        if (!$handler || !$request) return false;

        $url = $request->getCompleteUrl();

        // Hanya tangkap $$$call$$$ (AJAX OJS)
        if (strpos($url, '$$$call$$$') === false) return false;

        $data = [
            'type'         => 'ajax_call',
            'handler_class'=> get_class($handler),
            'url'          => $url,
            'method'       => $_SERVER['REQUEST_METHOD'] ?? 'GET',
            'post_keys'    => array_keys($_POST), // hanya key, bukan value
            'user_id'      => $this->_getCurrentUserId(),
            'ts'           => time(),
        ];

        $this->_sender->send($data);
        return false;
    }

    private function _scanRenderedHtml($html)
    {
        $threats = [];
        $seen    = [];
 
        foreach ($this->_scanPatterns as [$pattern, $severity, $description]) {
            if (preg_match($pattern, $html, $matches)) {
                // Deduplikasi — jangan report pattern yang sama dua kali
                $key = md5($pattern . $matches[0]);
                if (isset($seen[$key])) continue;
                $seen[$key] = true;
 
                $threats[] = [
                    'severity'    => $severity,
                    'description' => $description,
                    'match'       => substr($matches[0], 0, 200), // trim biar tidak terlalu panjang
                    'url'         => $_SERVER['REQUEST_URI'] ?? '',
                ];
            }
        }
 
        return $threats;
    }

    // ── Helpers ──────────────────────────────────────────────────────

    /**
     * Hash hanya bagian HTML yang stabil.
     * Strategi: strip semua tag dinamis, ambil text content dari
     * selector yang sudah didefinisikan di $_stableSelectors.
     *
     * Ini menghindari false positive dari:
     * - View counter
     * - Timestamp
     * - CSRF token
     * - Dynamic URL dengan query string
     */
    private function _hashStableContent($html)
    {
        // Gunakan DOMDocument untuk extract bagian stabil
        // Suppress warning karena HTML OJS tidak selalu valid
        $dom = new DOMDocument();
        libxml_use_internal_errors(true);
        $dom->loadHTML('<?xml encoding="UTF-8">' . $html);
        libxml_clear_errors();

        $stableText = '';

        foreach ($this->_stableSelectors as $selector) {
            $nodes = $this->_querySelectorAll($dom, $selector);
            foreach ($nodes as $node) {
                // Ambil text content saja, buang HTML tags
                $stableText .= trim($node->textContent) . "\n";
            }
        }

        // Fallback: kalau tidak ada selector yang match,
        // hash hanya bagian <main> atau <body> dengan dynamic parts distrip
        if (empty(trim($stableText))) {
            $stableText = $this->_stripDynamicParts($html);
        }

        return hash('sha256', $stableText);
    }

    /**
     * Implementasi querySelector sederhana tanpa ekstensi tambahan.
     * OJS 3.3 tidak guarantee ada DOMXPath yang lengkap.
     */
    private function _querySelectorAll($dom, $selector)
    {
        // Parse selector sederhana: tag.class atau div#id
        $nodes = [];
        $xpath = new DOMXPath($dom);

        // Konversi CSS selector ke XPath sederhana
        if (strpos($selector, '.') !== false) {
            [$tag, $class] = explode('.', $selector, 2);
            $xpathQuery = "//{$tag}[contains(@class, '{$class}')]";
        } elseif (strpos($selector, '#') !== false) {
            [$tag, $id] = explode('#', $selector, 2);
            $xpathQuery = "//{$tag}[@id='{$id}']";
        } else {
            $xpathQuery = "//{$selector}";
        }

        try {
            $result = $xpath->query($xpathQuery);
            if ($result) {
                foreach ($result as $node) {
                    $nodes[] = $node;
                }
            }
        } catch (Exception $e) {
            // Silent fail
        }

        return $nodes;
    }

    /**
     * Strip bagian yang selalu dynamic dari HTML:
     * - CSRF tokens
     * - View/download counters  
     * - Timestamp dan tanggal render
     * - Query string dari URL
     */
    private function _stripDynamicParts($html)
    {
        $patterns = [
            '/name="csrfToken"[^>]*value="[^"]*"/i',
            '/\d{1,3}(,\d{3})* (view|download|read)s?/i',
            '/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/i',
            '/\?[a-zA-Z0-9=&_%\-]{0,200}/',
        ];

        foreach ($patterns as $pattern) {
            $html = preg_replace($pattern, '', $html);
        }

        // Strip semua HTML tags, ambil text saja
        return strip_tags($html);
    }

    private function _detectPageType($template)
    {
        $map = [
            'frontend/pages/article'     => 'article_detail',
            'frontend/pages/issue'       => 'issue_detail',
            'frontend/pages/index'       => 'journal_index',
            'dashboard/index'            => 'dashboard',
            'management/settings'        => 'settings',
            'submission/wizard'          => 'submission_wizard',
        ];

        foreach ($map as $pattern => $type) {
            if (strpos($template, $pattern) !== false) return $type;
        }

        return 'other';
    }

    private function _getCurrentUserId()
    {
        try {
            $user = Application::get()->getRequest()->getUser();
            return $user ? $user->getId() : null;
        } catch (Exception $e) {
            return null;
        }
    }
}