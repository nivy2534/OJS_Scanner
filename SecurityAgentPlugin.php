<?php

require_once(dirname(__FILE__) . '/AgentConfig.php');
require_once(dirname(__FILE__) . '/collectors/RequestCollector.php');
require_once(dirname(__FILE__) . '/collectors/ResponseCollector.php');
require_once(dirname(__FILE__) . '/collectors/FileIntegrityCollector.php');
require_once(dirname(__FILE__) . '/collectors/SemgrepCollector.php');
require_once(dirname(__FILE__) . '/reporters/ResultSender.php');

/**
 * @file plugins/generic/securityAgent/SecurityAgentPlugin.php
 *
 * Security Agent Plugin untuk OJS 3.3.x
 *
 * Entry point plugin. Tugasnya hanya:
 * 1. Register ke OJS plugin system
 * 2. Daftarkan hooks sesuai collector yang aktif
 * 3. Delegate semua logika ke masing-masing collector
 *
 * Tidak ada business logic di sini — semua ada di collector.
 */
class SecurityAgentPlugin extends GenericPlugin
{
    /** @var ResultSender */
    private $_sender;

    // ── OJS Plugin API ───────────────────────────────────────────────

    public function register($category, $path, $mainContextId = null)
    {
        $success = parent::register($category, $path, $mainContextId);

        if ($success && $this->getEnabled()) {
            $this->_sender = new ResultSender();
            $this->_registerHooks();
        }

        return $success;
    }

    public function getDisplayName()
    {
        return AgentConfig::AGENT_NAME;
    }

    public function getDescription()
    {
        return 'Security monitoring agent untuk OJS — bagian dari platform security assessment.';
    }

    /**
     * Tampilkan form settings di halaman admin plugin OJS.
     */
    public function manage($args, $request)
    {
        switch ($request->getUserVar('verb')) {
            case 'settings':
                $this->import('settings.AgentSettingsForm');
                $form = new AgentSettingsForm($this);

                if ($request->getUserVar('save')) {
                    $form->readInputData();
                    if ($form->validate()) {
                        $form->execute();
                        return new JSONMessage(true);
                    }
                }

                $form->initData();
                return new JSONMessage(true, $form->fetch($request));
        }
        return parent::manage($args, $request);
    }

    public function getActions($request, $verb)
    {
        $router = $request->getRouter();
        import('lib.pkp.classes.linkAction.request.AjaxModal');
        return array_merge(
            [
                new LinkAction(
                    'settings',
                    new AjaxModal(
                        $router->url($request, null, null, 'manage', null, [
                            'verb'   => 'settings',
                            'plugin' => $this->getName(),
                            'category' => 'generic',
                        ]),
                        $this->getDisplayName()
                    ),
                    __('manager.plugins.settings'),
                    null
                ),
            ],
            parent::getActions($request, $verb)
        );
    }

    // ── Hook Registration ────────────────────────────────────────────

    /**
     * Daftarkan hooks berdasarkan collector yang aktif di AgentConfig.
     * Tambah hook baru di sini kalau mau extend fungsionalitas.
     */
    private function _registerHooks()
    {
        $collectors = AgentConfig::COLLECTORS;

        // ── Request Collector ────────────────────────────────────────
        if (!empty($collectors['request'])) {
            $rc = new RequestCollector($this->_sender);

            HookRegistry::register(
                'LoadHandler',
                [$rc, 'onLoadHandler']
            );

            HookRegistry::register(
                'Form::validate',
                [$rc, 'onFormValidate']
            );
        }

        // ── Response Collector ───────────────────────────────────────
        if (!empty($collectors['response'])) {
            $rsc = new ResponseCollector($this->_sender);

            HookRegistry::register(
                'TemplateManager::display',
                [$rsc, 'onTemplateDisplay']
            );

            HookRegistry::register(
                'PKPHandler::setupTemplate',
                [$rsc, 'onSetupTemplate']
            );
        }

        // ── File Integrity Collector ─────────────────────────────────
        if (!empty($collectors['integrity'])) {
            $fic = new FileIntegrityCollector($this->_sender);

            HookRegistry::register(
                'AcronPlugin::parseCronTab',
                [$fic, 'onCronTab']
            );
        }

        // ── Semgrep Collector ────────────────────────────────────────
        if (!empty($collectors['semgrep'])) {
            $sc = new SemgrepCollector($this->_sender);
            
            HookRegistry::register(
                'PluginRegistry::categoryLoaded::generic',
                [$sc, 'onPluginInstalled']
            );

            HookRegistry::register(
                'PKPFileService::add',
                [$sc, 'onFileUploaded']
            );

            HookRegistry::register(
                'AcronPlugin::parseCronTab',
                [$sc, 'onCronTab']
            );
        }
    }
    public function callbackParseCronTab($hookName, $params)
    {
        $taskFilesPath =& $params[0];
        $taskFilesPath[] = $this->getPluginPath() . '/scheduledTasks.xml';
        error_log('[SecurityAgent] scheduledTasks.xml registered');
        return false;
    }
}