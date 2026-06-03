<?php

import('lib.pkp.classes.form.Form');

/**
 * @file plugins/generic/securityAgent/settings/AgentSettingsForm.php
 *
 * Form settings plugin di halaman admin OJS.
 * Untuk sekarang: tampilkan status agent + tombol run integrity check.
 * Bisa diextend nanti untuk konfigurasi platform URL, token, dll.
 */
class AgentSettingsForm extends Form
{
    /** @var int Context ID (journal) */
    private $_contextId;

    /** @var SecurityAgentPlugin */
    private $_plugin;

    public function __construct($plugin)
    {
        $this->_plugin    = $plugin;
        $this->_contextId = Application::get()
            ->getRequest()->getContext()->getId();

        parent::__construct(
            $plugin->getTemplateResource('settings/agentSettings.tpl')
        );

        // Validasi: platform URL harus valid URL
        $this->addCheck(new FormValidatorURL(
            $this, 'platformUrl', 'optional',
            'plugins.generic.securityAgent.settings.platformUrlInvalid'
        ));

        $this->addCheck(new FormValidatorPost($this));
        $this->addCheck(new FormValidatorCSRF($this));
    }

    public function initData()
    {
        $this->setData('platformUrl', $this->_plugin->getSetting(
            $this->_contextId, 'platformUrl'
        ) ?? AgentConfig::PLATFORM_URL);

        $this->setData('agentEnabled', $this->_plugin->getSetting(
            $this->_contextId, 'agentEnabled'
        ) ?? true);

        $this->setData('agentVersion', AgentConfig::AGENT_VERSION);
    }

    public function readInputData()
    {
        $this->readUserVars(['platformUrl', 'agentEnabled']);
    }

    public function execute(...$functionArgs)
    {
        $this->_plugin->updateSetting(
            $this->_contextId,
            'platformUrl',
            $this->getData('platformUrl'),
            'string'
        );

        $this->_plugin->updateSetting(
            $this->_contextId,
            'agentEnabled',
            $this->getData('agentEnabled'),
            'bool'
        );

        parent::execute(...$functionArgs);
    }
}