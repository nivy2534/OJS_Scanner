<?php

require_once(dirname(__DIR__) . '/AgentConfig.php');

/**
 * @file plugins/generic/securityAgent/collectors/FileIntegrityCollector.php
 *
 * Monitor integritas file PHP OJS.
 * Strategi: bukan hash semua file, tapi hanya direktori yang
 * didefinisikan di AgentConfig::WATCH_DIRS.
 *
 * Untuk menghindari false positive akibat OJS update:
 * - Core OJS files → bandingkan dengan checksums resmi OJS
 * - Custom/plugin files → bandingkan dengan snapshot sebelumnya
 */
class FileIntegrityCollector
{
    /** @var ResultSender */
    private $_sender;

    /** @var string Path absolut ke OJS root */
    private $_ojsRoot;

    /** @var string Path ke file snapshot hash */
    private $_snapshotPath;

    public function __construct($sender)
    {
        $this->_sender      = $sender;
        $this->_ojsRoot     = BASE_SYS_DIR; // konstanta OJS
        $this->_snapshotPath = $this->_ojsRoot
            . '/cache/security_agent_snapshot.json';
    }

    // ── Hook Handlers ────────────────────────────────────────────────

    /**
     * Register cron job via AcronPlugin.
     * Integrity check berjalan sekali sehari secara otomatis.
     *
     * Hook: AcronPlugin::parseCronTab
     */
    public function onCronTab($hookName, $params)
    {
        $taskFilesPath =& $params[0];
        $taskFilesPath[] = $this->_getPluginPath() . '/scheduledTasks.xml';
        return false;
    }

    /**
     * Entry point utama — jalankan integrity check.
     * Dipanggil oleh cron atau manual dari settings page.
     */
    public function runCheck()
    {
        $current  = $this->_scanWatchDirs();
        $snapshot = $this->_loadSnapshot();
        $changes  = $this->_diff($snapshot, $current);

        // Simpan snapshot terbaru
        $this->_saveSnapshot($current);

        if (empty($changes)) return;

        // Kirim perubahan ke platform
        $data = [
            'type'    => 'file_integrity',
            'changes' => $changes,
            'checked' => count($current),
            'ts'      => time(),
        ];

        $this->_sender->send($data);

        if (AgentConfig::DEBUG) {
            error_log('[SecurityAgent] Integrity: ' . count($changes) . ' change(s) detected');
        }
    }

    // ── Core Logic ───────────────────────────────────────────────────

    /**
     * Scan semua direktori di WATCH_DIRS dan return array:
     * [ 'relative/path/file.php' => 'sha256hash', ... ]
     */
    private function _scanWatchDirs()
    {
        $hashes = [];

        foreach (AgentConfig::WATCH_DIRS as $dir) {
            $fullPath = $this->_ojsRoot . '/' . ltrim($dir, '/');

            if (is_file($fullPath)) {
                // Entry tunggal (misal: config.inc.php)
                $rel = ltrim($dir, '/');
                $hashes[$rel] = $this->_hashFile($fullPath);
            } elseif (is_dir($fullPath)) {
                // Rekursif scan direktori
                $this->_scanDir($fullPath, $hashes);
            }
        }

        return $hashes;
    }

    private function _scanDir($dir, &$hashes)
    {
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator(
                $dir,
                RecursiveDirectoryIterator::SKIP_DOTS
            )
        );

        foreach ($iterator as $file) {
            if (!$file->isFile()) continue;

            // Hanya PHP dan config files
            $ext = strtolower($file->getExtension());
            if (!in_array($ext, ['php', 'inc', 'xml', 'tpl'])) continue;

            $absPath = $file->getRealPath();
            $relPath = str_replace($this->_ojsRoot . '/', '', $absPath);

            $hashes[$relPath] = $this->_hashFile($absPath);
        }
    }

    /**
     * Bandingkan snapshot lama dengan scan terbaru.
     * Return: array perubahan dengan kategori added/modified/deleted.
     */
    private function _diff($old, $new)
    {
        $changes = [];

        // File baru atau dimodifikasi
        foreach ($new as $path => $hash) {
            if (!isset($old[$path])) {
                $changes[] = [
                    'status' => 'added',
                    'path'   => $path,
                    'hash'   => $hash,
                ];
            } elseif ($old[$path] !== $hash) {
                $changes[] = [
                    'status'   => 'modified',
                    'path'     => $path,
                    'old_hash' => $old[$path],
                    'new_hash' => $hash,
                ];
            }
        }

        // File yang dihapus
        foreach ($old as $path => $hash) {
            if (!isset($new[$path])) {
                $changes[] = [
                    'status' => 'deleted',
                    'path'   => $path,
                    'hash'   => $hash,
                ];
            }
        }

        return $changes;
    }

    // ── Snapshot Management ──────────────────────────────────────────

    private function _loadSnapshot()
    {
        if (!file_exists($this->_snapshotPath)) return [];

        $content = file_get_contents($this->_snapshotPath);
        $data    = json_decode($content, true);

        return is_array($data) ? $data : [];
    }

    private function _saveSnapshot($hashes)
    {
        $dir = dirname($this->_snapshotPath);
        if (!is_dir($dir)) mkdir($dir, 0755, true);

        file_put_contents(
            $this->_snapshotPath,
            json_encode($hashes, JSON_PRETTY_PRINT)
        );
    }

    // ── Utilities ────────────────────────────────────────────────────

    private function _hashFile($path)
    {
        return hash_file('sha256', $path);
    }

    private function _getPluginPath()
    {
        return dirname(__DIR__);
    }
}