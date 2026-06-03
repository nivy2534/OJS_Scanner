<?php

require_once(dirname(__DIR__) . '/AgentConfig.php');

/**
 * @file plugins/generic/securityAgent/reporters/ResultSender.php
 *
 * Kirim data dari semua collector ke platform pusat via HTTP.
 * Kalau platform tidak reachable → simpan ke local log.
 *
 * Semua collector pakai class ini — tidak ada HTTP logic di collector.
 */
class ResultSender
{
    /** @var string URL platform pusat */
    private $_platformUrl;

    /** @var string Token autentikasi */
    private $_token;

    public function __construct()
    {
        $this->_platformUrl = AgentConfig::PLATFORM_URL;
        $this->_token       = AgentConfig::PLATFORM_TOKEN;
    }

    /**
     * Kirim satu event ke platform.
     * Fire-and-forget: tidak block request OJS kalau platform lambat.
     *
     * @param array $data Data dari collector
     */
    public function send(array $data)
    {
        // Tambahkan metadata agent
        $payload = array_merge($data, [
            'agent_version' => AgentConfig::AGENT_VERSION,
            'host'          => $_SERVER['HTTP_HOST'] ?? 'unknown',
        ]);

        $sent = $this->_sendHttp($payload);

        // Fallback ke local log kalau HTTP gagal
        if (!$sent && AgentConfig::LOCAL_LOG_ENABLED) {
            $this->_writeLocalLog($payload);
        }
    }

    // ── Transport ────────────────────────────────────────────────────

    private function _sendHttp(array $payload)
    {
        $body = json_encode($payload);

        $context = stream_context_create([
            'http' => [
                'method'        => 'POST',
                'header'        => implode("\r\n", [
                    'Content-Type: application/json',
                    'Authorization: Bearer ' . $this->_token,
                    'Content-Length: ' . strlen($body),
                    'X-Agent-Version: ' . AgentConfig::AGENT_VERSION,
                ]),
                'content'       => $body,
                'timeout'       => AgentConfig::SEND_TIMEOUT,
                'ignore_errors' => true,
            ],
        ]);

        try {
            $result = @file_get_contents($this->_platformUrl, false, $context);
            return $result !== false;
        } catch (Exception $e) {
            if (AgentConfig::DEBUG) {
                error_log('[SecurityAgent] Send failed: ' . $e->getMessage());
            }
            return false;
        }
    }

    private function _writeLocalLog(array $payload)
    {
        $logPath = BASE_SYS_DIR . '/' . AgentConfig::LOCAL_LOG_PATH;
        $dir     = dirname($logPath);

        if (!is_dir($dir)) mkdir($dir, 0755, true);

        $line = json_encode($payload) . "\n";

        file_put_contents($logPath, $line, FILE_APPEND | LOCK_EX);
    }
}