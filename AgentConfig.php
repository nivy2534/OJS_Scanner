<?php

/**
 * @file plugins/generic/securityAgent/AgentConfig.php
 *
 * Konfigurasi global Security Agent.
 * Semua konstanta dan default value ada di sini —
 * tidak perlu ubah file lain kalau mau ganti perilaku agent.
 */

class AgentConfig
{
    // ── Identitas agent ─────────────────────────────────────────────
    const AGENT_VERSION  = '1.0.0';
    const AGENT_NAME     = 'OJS Security Agent';

    // ── Endpoint platform pusat ──────────────────────────────────────
    // Ganti sesuai URL server pusat kamu
    const PLATFORM_URL = 'http://host.docker.internal:60000/collect';
    const PLATFORM_TOKEN = 'AlfiGanteng';

    // Di AgentConfig.php, tambah setelah PLATFORM_TOKEN:
    const SCAN_SERVER_URL   = 'http://host.docker.internal:60000';
    const SCAN_SERVER_TOKEN = 'AlfiGanteng';
    const SCAN_SERVER_TIMEOUT = 10;

    // ── Timeout HTTP ke platform (detik) ────────────────────────────
    const SEND_TIMEOUT   = 5;

    // ── Collectors yang aktif ────────────────────────────────────────
    // Set false untuk disable collector tertentu tanpa hapus kodenya
    const COLLECTORS = [
        'request'   => true,   // RequestCollector  — monitor input
        'response'  => true,   // ResponseCollector — monitor output render
        'integrity' => false,
        'semgrep' => true // FileIntegrityCollector — hash file PHP
                               // (disable dulu, enable kalau sudah siap)
    ];

    // ── Filter request ───────────────────────────────────────────────
    // Request dengan path ini tidak akan di-collect (terlalu noisy)
    const SKIP_PATHS = [
        '/favicon.ico',
        '/$$$call$$$/page/page/css',
        '/notificationFeed',
    ];

    // ── File integrity ───────────────────────────────────────────────
    // Direktori yang di-watch untuk integrity check
    // Relatif terhadap OJS base path
    const WATCH_DIRS = [
        'plugins/generic',
        'plugins/blocks',
        'config.inc.php',
    ];

    // ── Logging lokal ────────────────────────────────────────────────
    // Kalau platform tidak reachable, hasil disimpan ke file ini
    const LOCAL_LOG_ENABLED = true;
    const LOCAL_LOG_PATH    = 'cache/securityAgent.log'; // relatif ke OJS root

    // ── Mode debug ───────────────────────────────────────────────────
    // true = print error ke PHP error log, false = silent
    const DEBUG = true;
}