<?php
/**
 * This file is a part of the CIDRAM package.
 * Homepage: https://cidram.github.io/
 *
 * CIDRAM COPYRIGHT 2016 and beyond by Caleb Mazalevskis (Maikuolan).
 *
 * License: GNU/GPLv2
 * @see LICENSE.txt
 *
 * This file: The logs page (last modified: 2023.12.13).
 */

namespace phpMussel\FrontEnd;

if (!isset($Page) || $Page !== 'logs' || ($this->Permissions !== 1 && $this->Permissions !== 2)) {
    die;
}

/** Page initial prepwork. */
$this->initialPrepwork($FE, $this->Loader->L10N->getString('link.Logs'), $this->Loader->L10N->getString('tip.Logs'), false);

/** Parse output. */
$FE['FE_Content'] = $this->Loader->parse($FE, $this->Loader->readFile($this->getAssetPath('_logs.html')), true);

/** Initialise array for fetching logs data. */
$FE['LogFiles'] = ['Files' => $this->logsRecursiveList(), 'Out' => ''];

/** Text mode switch link base. */
$FE['TextModeSwitchLink'] = '';

/** How to display the log data? */
if (empty($this->QueryVariables['text-mode']) || $this->QueryVariables['text-mode'] === 'false') {
    $FE['TextModeLinks'] = 'false';
    $TextMode = false;
} else {
    $FE['TextModeLinks'] = 'true';
    $TextMode = true;
}

/** Define log data. */
if (empty($this->QueryVariables['logfile'])) {
    $FE['logfileData'] = $this->Loader->L10N->getString('label.No log file selected');
} elseif (empty($FE['LogFiles']['Files'][$this->QueryVariables['logfile']])) {
    $FE['logfileData'] = $this->Loader->L10N->getString('label.Selected log file doesn_t exist');
} else {
    $FE['TextModeSwitchLink'] .= '?phpmussel-page=logs&logfile=' . $this->QueryVariables['logfile'] . '&text-mode=';
    if (strtolower(substr($this->QueryVariables['logfile'], -3)) === '.gz') {
        $FE['logfileData'] = $this->Loader->readFileGZ($this->QueryVariables['logfile']);
    } else {
        $FE['logfileData'] = $this->Loader->readFile($this->QueryVariables['logfile']);
    }
    $FE['logfileData'] = $TextMode ? str_replace(
        ['<', '>', "\r", "\n"],
        ['&lt;', '&gt;', '', "<br />\n"],
        $FE['logfileData']
    ) : str_replace(
        ['<', '>', "\r"],
        ['&lt;', '&gt;', ''],
        $FE['logfileData']
    );
    $FE['mod_class_nav'] = ' big';
    $FE['mod_class_right'] = ' extend';
}
if (empty($FE['mod_class_nav'])) {
    $FE['mod_class_nav'] = ' extend';
    $FE['mod_class_right'] = ' big';
}
if (empty($FE['TextModeSwitchLink'])) {
    $FE['TextModeSwitchLink'] .= '?phpmussel-page=logs&text-mode=';
}

/** Text mode switch link formatted. */
$FE['TextModeSwitchLink'] = sprintf(
    $this->Loader->L10N->getString('link.Text formatting'),
    $FE['TextModeSwitchLink']
);

/** Prepare log data formatting. */
if (!$TextMode) {
    $FE['logfileData'] = '<textarea id="logsTA" readonly>' . $FE['logfileData'] . '</textarea>';
} else {
    $this->formatter($FE['logfileData']);
}

/** Process logs list. */
foreach ($FE['LogFiles']['Files'] as $Filename => $Filesize) {
    $FE['LogFiles']['Out'] .= sprintf(
        '      <a href="?phpmussel-page=logs&logfile=%1$s&text-mode=%3$s">%1$s</a> – %2$s<br />',
        $Filename ?? '',
        $Filesize ?? '',
        $FE['TextModeLinks'] ?? ''
    ) . "\n";
}

/** Calculate page load time (useful for debugging). */
$FE['ProcessTime'] = microtime(true) - $_SERVER['REQUEST_TIME_FLOAT'];
$FE['ProcessTime'] = '<br />' . sprintf(
    $this->Loader->L10N->getPlural($FE['ProcessTime'], 'label.Page request completed in %s seconds'),
    '<span class="txtRd">' . $this->NumberFormatter->format($FE['ProcessTime'], 3) . '</span>'
);

/** Set the log files list or the no log files available message. */
$FE['LogFiles'] = $FE['LogFiles']['Out'] ?: $this->Loader->L10N->getString('label.No log files available');

/** Send output. */
echo $this->sendOutput($FE);

return;
