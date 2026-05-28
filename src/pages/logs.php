<?php
/**
 * This file is a part of the phpMussel\FrontEnd package.
 * Homepage: https://phpmussel.github.io/
 *
 * PHPMUSSEL COPYRIGHT 2013 AND BEYOND BY THE PHPMUSSEL TEAM.
 *
 * License: GNU/GPLv2
 * @see LICENSE.txt
 *
 * This file: The logs page (last modified: 2026.05.28).
 */

namespace phpMussel\FrontEnd;

if (!isset($Page) || $Page !== 'logs' || ($this->Permissions !== 1 && $this->Permissions !== 2)) {
    die;
}

/** Page initial prepwork. */
$this->initialPrepwork($FE, $this->Loader->L10N->getString('link.Logs'), $this->Loader->L10N->getString('tip.Logs'));

/** Parse output. */
$FE['FE_Content'] = $this->Loader->parse($FE, $this->Loader->readFile($this->getAssetPath('_logs.html')), true);

/** Initialise array for fetching logs data. */
$FE['LogFiles'] = ['Files' => $this->logsRecursiveList(), 'Out' => ''];

/** Download a log file. */
if (
    isset($this->QueryVariables['text-mode'], $this->QueryVariables['logfile'], $FE['LogFiles']['Files'][$this->QueryVariables['logfile']]) &&
    $this->QueryVariables['text-mode'] === 'download'
) {
    \header('Content-Type: application/octet-stream');
    \header('Content-Transfer-Encoding: Binary');
    \header('Content-disposition: attachment; filename="' . \basename($this->QueryVariables['logfile']) . '"');
    echo $this->Loader->readFile($this->Vault . $this->QueryVariables['logfile']);
    return;
}

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
    $FE['mod_class_right'] = '';
} elseif (empty($FE['LogFiles']['Files'][$this->QueryVariables['logfile']])) {
    $FE['logfileData'] = $this->Loader->L10N->getString('label.Selected log file doesn_t exist');
    $FE['mod_class_right'] = '';
} else {
    $FE['TextModeSwitchLink'] .= '?phpmussel-page=logs&logfile=' . $this->QueryVariables['logfile'] . '&text-mode=';
    if (\strtolower(\substr($this->QueryVariables['logfile'], -3)) === '.gz') {
        $FE['logfileData'] = $this->Loader->readFileGZ($this->QueryVariables['logfile']);
    } else {
        $FE['logfileData'] = $this->Loader->readFile($this->QueryVariables['logfile']);
    }
    $FE['logfileData'] = $TextMode ? \str_replace(
        ['<', '>', "\r", "\n"],
        ['&lt;', '&gt;', '', "<br />\n"],
        $FE['logfileData']
    ) : \str_replace(
        ['<', '>', "\r"],
        ['&lt;', '&gt;', ''],
        $FE['logfileData']
    );
    $FE['mod_class_right'] = ' extend';
}
if (empty($FE['TextModeSwitchLink'])) {
    $FE['TextModeSwitchLink'] .= '?phpmussel-page=logs&text-mode=';
}

/** Text mode switch link formatted. */
$FE['TextModeSwitchLink'] = \sprintf(
    $this->Loader->L10N->getString('link.Text formatting'),
    $FE['TextModeSwitchLink']
);

/** Prepare log data formatting. */
if (!$TextMode) {
    $FE['logfileData'] = '<textarea id="logsTA" readonly>' . $FE['logfileData'] . '</textarea>';
} else {
    $this->formatter($FE['logfileData']);
}

$DownloadLabel = $this->Loader->L10N->getString('field.Download');

/** Generate a list of the logs. */
foreach ($FE['LogFiles']['Files'] as $Filename => $Filesize) {
    $FE['LogFiles']['Out'] .= \sprintf(
        '        <a href="?phpmussel-page=logs&logfile=%1$s&text-mode=%3$s">%1$s</a> – %2$s <a title="%4$s" href="?phpmussel-page=logs&logfile=%1$s&text-mode=download"><span class="navicon download"></span></a><br />',
        $Filename ?? '',
        $Filesize ?? '',
        $FE['TextModeLinks'] ?? '',
        $DownloadLabel
    ) . "\n";
}
unset($Filesize, $Filename, $DownloadLabel);

/** Calculate page load time (useful for debugging). */
$FE['ProcessTime'] = \microtime(true) - $_SERVER['REQUEST_TIME_FLOAT'];
$FE['ProcessTime'] = '<br />' . \sprintf(
    $this->Loader->L10N->getPlural($FE['ProcessTime'], 'label.Page request completed in %s seconds'),
    '<span class="txtRd">' . $this->NumberFormatter->format($FE['ProcessTime'], 3) . '</span>'
);

/** Set the log files list or the no log files available message. */
if ($FE['LogFiles']['Out'] === '') {
    $FE['LogFiles'] = $this->Loader->L10N->getString('label.No log files available');
} else {
    $FE['LogFiles'] = \sprintf('        <div class="subNav">%s</div>', $this->Loader->L10N->getString('link.Logs')) . "\n" . $FE['LogFiles']['Out'];
}

/** Send output. */
echo $this->sendOutput($FE);

return;
