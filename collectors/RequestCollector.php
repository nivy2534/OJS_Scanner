<?php

require_once(dirname(__DIR__) . '/AgentConfig.php');

/**
 * @file plugins/generic/securityAgent/collectors/RequestCollector.php
 *
 * Monitor semua HTTP request dan form input yang masuk ke OJS.
 * Tidak memblokir request — hanya collect dan kirim ke platform.
 */
class RequestCollector
{
    /** @var ResultSender */
    private $_sender;

    public function __construct($sender)
    {
        $this->_sender = $sender;
    }

    // ── Hook Handlers ────────────────────────────────────────────────

    /**
     * Dipanggil setiap kali OJS selesai resolve handler untuk request.
     * Tangkap: URL, method, GET params, headers.
     *
     * Hook: LoadHandler
     * Params: [&$handler, &$op, &$request]
     */
    public function onLoadHandler($hookName, $params)
    {
        // OJS 3.3: params = [&$page, &$op, &$sourceFile]
        // Request diambil dari Application, bukan dari params
        error_log('[SecurityAgent] onLoadHandler called!');
        $page = $params[0] ?? '';
        $op   = $params[1] ?? '';

        // Ambil request dari Application singleton
        $request = Application::get()->getRequest();
        if (!$request) return false;

        $url = $request->getCompleteUrl();

        if ($this->_shouldSkip($url)) return false;

        $data = [
            'type'    => 'request',
            'url'     => $url,
            'page'    => $page,
            'op'      => $op,
            'method'  => $_SERVER['REQUEST_METHOD'] ?? 'GET',
            'get'     => $this->_sanitizeParams($_GET),
            'headers' => $this->_collectHeaders(),
            'ip'      => $request->getRemoteAddr(),
            'user_id' => $this->_getCurrentUserId(),
            'ts'      => time(),
        ];

        $this->_sender->send($data);
        return false;
    }

    /**
     * Dipanggil saat form OJS di-validate.
     * Tangkap: form fields (POST data) sebelum diproses OJS.
     *
     * Hook: Form::validate
     * Params: [&$form]
     */
    public function onFormValidate($hookName, $params)
    {
        $form = $params[0] ?? null;
        if (!$form) return false;

        // Ambil data form — pakai getData() bukan $_POST langsung
        // agar ikut proses sanitasi OJS
        $formData = method_exists($form, 'getData')
            ? $form->_data ?? []
            : [];

        // Hapus field sensitif sebelum kirim
        $formData = $this->_stripSensitiveFields($formData);

        if (empty($formData)) return false;

        $data = [
            'type'      => 'form_input',
            'form_class'=> get_class($form),
            'fields'    => $formData,
            'url'       => $_SERVER['REQUEST_URI'] ?? '',
            'method'    => 'POST',
            'user_id'   => $this->_getCurrentUserId(),
            'ts'        => time(),
        ];

        $this->_sender->send($data);
        return false;
    }

    // ── Helpers ──────────────────────────────────────────────────────

    private function _shouldSkip($url)
    {
        foreach (AgentConfig::SKIP_PATHS as $path) {
            if (strpos($url, $path) !== false) return true;
        }
        return false;
    }

    private function _sanitizeParams($params)
    {
        // Trim nilai, buang key yang terlalu panjang (anomali)
        $clean = [];
        foreach ($params as $k => $v) {
            if (strlen($k) > 100) continue;
            $clean[$k] = is_array($v) ? $v : substr((string)$v, 0, 512);
        }
        return $clean;
    }

    private function _stripSensitiveFields($data)
    {
        $sensitive = ['password', 'csrfToken', 'token', 'secret'];
        foreach ($sensitive as $field) {
            if (isset($data[$field])) {
                $data[$field] = '[REDACTED]';
            }
        }
        return $data;
    }

    private function _collectHeaders()
    {
        $headers = [];
        $interesting = [
            'HTTP_USER_AGENT', 'HTTP_REFERER',
            'HTTP_X_FORWARDED_FOR', 'HTTP_ACCEPT',
            'CONTENT_TYPE',
        ];
        foreach ($interesting as $key) {
            if (!empty($_SERVER[$key])) {
                $headers[$key] = $_SERVER[$key];
            }
        }
        return $headers;
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