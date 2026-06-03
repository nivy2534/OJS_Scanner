<?php

error_log('[SecurityAgent] index.php loaded');

require_once('SecurityAgentPlugin.php');
return new SecurityAgentPlugin();