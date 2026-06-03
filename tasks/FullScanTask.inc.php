<?php

import('lib.pkp.classes.scheduledTask.ScheduledTask');
require_once(dirname(__DIR__) . '/AgentConfig.php');
require_once(dirname(__DIR__) . '/reporters/ResultSender.php');

class FullScanTask extends ScheduledTask
{
    public function executeActions()
    {
        error_log('[SecurityAgent] FullScanTask::executeActions() called');
        
        $scanServerUrl = AgentConfig::SCAN_SERVER_URL . '/scan';

        $payload = json_encode([
            'path'  => '.',
            'event' => 'scheduled',
            'host'  => php_uname('n'),
            'ts'    => time(),
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
                'timeout'       => 300,
                'ignore_errors' => true,
            ],
        ]);

        $response = @file_get_contents($scanServerUrl, false, $context);

        if ($response === false) {
            error_log('[SecurityAgent] FullScanTask: scan server tidak reachable');
            return false;
        }

        error_log('[SecurityAgent] FullScanTask: scan triggered, response=' . substr($response, 0, 100));
        return true;
    }
}