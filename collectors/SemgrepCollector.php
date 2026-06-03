<?php

require_once(dirname(__DIR__) . '/AgentConfig.php');

/**
 * @file plugins/generic/securityAgent/collectors/SemgrepCollector.php
 *
 * Trigger Semgrep scan via HTTP ke Docker container Python.
 * Tidak ada shell_exec() — semua lewat HTTP POST ke scan_server.py.
 *
 * Dua mode:
 * 1. Event-driven  → dipanggil saat plugin diinstall/diupdate
 * 2. Scheduled     → dipanggil oleh cron job harian
 */
class SemgrepCollector
{
    /** @var ResultSender */
    private $_sender;

    public function __construct($sender)
    {
        $this->_sender = $sender;
    }

    // ── Hook Handlers ────────────────────────────────────────────────

    /**
     * EVENT DRIVEN — dipanggil saat plugin baru diinstall di OJS.
     *
     * Hook: PluginRegistry::loadCategory
     * Dipanggil OJS setiap kali load plugin category.
     * Kita filter hanya yang baru (via flag di DB).
     */
    public function onPluginInstalled($hookName, $params)
    {
        error_log('[SecurityAgent][Semgrep] categoryLoaded called!');
        
        // categoryLoaded: params[0] = &$plugins (array)
        $plugins = $params[0] ?? [];
        error_log('[SecurityAgent][Semgrep] plugin count: ' . count($plugins));

        foreach ($plugins as $plugin) {
            $pluginPath = $plugin->getPluginPath();
            $isNew = $this->_isNewPlugin($pluginPath);
            error_log("[SecurityAgent][Semgrep] path={$pluginPath} isNew=" . ($isNew ? 'true' : 'false'));

            if ($isNew) {
                $this->_triggerScan($pluginPath, 'plugin_install');
                $this->_markPluginKnown($pluginPath);
            }
        }
        return false;
    }

    /**
     * EVENT DRIVEN — dipanggil saat file diupload via OJS file manager.
     * Tangkap upload file PHP yang mencurigakan.
     *
     * Hook: PKPFileService::add
     */
    public function onFileUploaded($hookName, $params)
    {
        $file = $params[0] ?? null;
        if (!$file) return false;

        $path = $file['path'] ?? '';

        // Hanya scan file PHP/tpl yang diupload
        $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
        if (!in_array($ext, ['php', 'inc', 'tpl'])) return false;

        $this->_triggerScan($path, 'file_upload');
        return false;
    }

    /**
     * SCHEDULED — dipanggil oleh AcronPlugin (cron OJS).
     * Scan seluruh WATCH_DIRS secara menyeluruh.
     *
     * Hook: AcronPlugin::parseCronTab
     */
    public function onCronTab($hookName, $params)
    {
        $taskFilesPath =& $params[0];
        $taskFilesPath[] = dirname(__DIR__) . '/scheduledTasks.xml';
        return false;
    }

    /**
     * Entry point untuk scheduled scan — dipanggil oleh scheduledTasks.xml.
     * Scan semua direktori di WATCH_DIRS.
     */
    public function runScheduledScan()
    {
        echo "[SecurityAgent] Running scheduled Semgrep scan...\n";

        foreach (AgentConfig::WATCH_DIRS as $dir) {
            $fullPath = BASE_SYS_DIR . '/' . ltrim($dir, '/');
            if (file_exists($fullPath)) {
                $this->_triggerScan($fullPath, 'scheduled');
            }
        }
    }

    // ── Core: Trigger Scan via HTTP ──────────────────────────────────

    /**
     * Kirim request ke scan_server.py di Docker.
     * POST /scan dengan payload path + event type.
     *
     * @param string $path     Path yang akan di-scan (absolut atau relatif ke OJS root)
     * @param string $event    Jenis event: plugin_install | file_upload | scheduled
     */
    private function _triggerScan($path, $event)
    {

        $scanServerUrl = AgentConfig::SCAN_SERVER_URL . '/scan';

        error_log("[SecurityAgent][Semgrep] Triggering scan: {$path} [{$event}]");
        error_log("[SecurityAgent][Semgrep] URL: " . AgentConfig::SCAN_SERVER_URL . '/scan');

        // Normalisasi path — selalu kirim relatif ke OJS root
        $relativePath = str_replace(BASE_SYS_DIR . '/', '', $path);

        $payload = json_encode([
            'path'    => $relativePath,
            'event'   => $event,
            'host'    => $_SERVER['HTTP_HOST'] ?? 'unknown',
            'ts'      => time(),
        ]);

        $context = stream_context_create([
            'http' => [
                'method'        => 'POST',
                'header'        => implode("\r\n", [
                    'Content-Type: application/json',
                    'Authorization: Bearer ' . AgentConfig::SCAN_SERVER_TOKEN,
                    'Content-Length: ' . strlen($payload),
                ]),
                'content'       => $payload,
                'timeout'       => AgentConfig::SCAN_SERVER_TIMEOUT,
                'ignore_errors' => true,
            ],
        ]);

        try {
            $response = @file_get_contents($scanServerUrl, false, $context);

            if ($response === false) {
                $this->_logError("Scan server tidak reachable: {$scanServerUrl}");
                return;
            }

            $result = json_decode($response, true);

            if (empty($result)) {
                $this->_logError("Scan server return empty response");
                return;
            }

            // Kalau ada findings, kirim ke platform pusat
            if (!empty($result['findings'])) {
                $this->_sender->send([
                    'type'     => 'semgrep_findings',
                    'event'    => $event,
                    'path'     => $relativePath,
                    'findings' => $result['findings'],
                    'summary'  => $result['summary'] ?? [],
                    'ts'       => time(),
                ]);

                $this->_logInfo(
                    count($result['findings']) . " finding(s) dari {$relativePath} [{$event}]"
                );
            } else {
                $this->_logInfo("Clean: {$relativePath} [{$event}]");
            }

        } catch (Exception $e) {
            $this->_logError("Exception saat trigger scan: " . $e->getMessage());
        }
    }

    // ── Plugin Tracking ──────────────────────────────────────────────

    /**
     * Cek apakah plugin ini belum pernah di-scan sebelumnya.
     * Pakai file JSON sederhana sebagai registry.
     */
    private function _isNewPlugin($pluginPath)
    {
        //return true;

        $known = $this->_loadKnownPlugins();
        return !in_array($pluginPath, $known);
    }

    private function _markPluginKnown($pluginPath)
    {
        $known   = $this->_loadKnownPlugins();
        $known[] = $pluginPath;
        file_put_contents(
            $this->_knownPluginsPath(),
            json_encode(array_unique($known))
        );
    }

    private function _loadKnownPlugins()
    {
        $path = $this->_knownPluginsPath();
        if (!file_exists($path)) return [];
        return json_decode(file_get_contents($path), true) ?? [];
    }

    private function _knownPluginsPath()
    {
        return BASE_SYS_DIR . '/cache/security_agent_known_plugins.json';
    }

    // ── Logging ──────────────────────────────────────────────────────

    private function _logInfo($msg)
    {
        if (AgentConfig::DEBUG) {
            error_log("[SecurityAgent][Semgrep] {$msg}");
        }
    }

    private function _logError($msg)
    {
        error_log("[SecurityAgent][Semgrep][ERROR] {$msg}");
    }
}