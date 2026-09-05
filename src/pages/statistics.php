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
 * This file: The statistics page (last modified: 2026.09.05).
 */

namespace phpMussel\FrontEnd;

if (!isset($Page) || $Page !== 'statistics' || empty($this->PermissionsMap['Statistics'])) {
    die;
}

/** Page initial prepwork. */
$this->initialPrepwork($FE, $this->Loader->L10N->getString('link.Statistics'), $this->Loader->L10N->getString('tip.Statistics'));

/** Display how to enable statistics if currently disabled. */
if (!$this->Loader->Configuration['core']['statistics']) {
    $FE['state_msg'] .= '<span class="txtRd">' . $this->Loader->L10N->getString('tip.Statistics tracking is currently disabled') . '</span><br />';
}

/** Generate confirm button. */
$FE['Confirm-ClearAll'] = $this->generateConfirm($this->Loader->L10N->getString('field.Clear all'), 'statForm');

/** Fetch statistics cache data. */
if ($this->Loader->InstanceCache['Statistics'] = ($this->Loader->Cache->getEntry('Statistics') ?: [])) {
    if (\is_string($this->Loader->InstanceCache['Statistics'])) {
        \unserialize($this->Loader->InstanceCache['Statistics']) ?: [];
    }
}

/** Clear statistics. */
if (!empty($_POST['ClearStats'])) {
    $this->Loader->Cache->deleteEntry('Statistics');
    $this->Loader->InstanceCache['Statistics'] = [];
    $FE['state_msg'] .= $this->Loader->L10N->getString('response.Statistics cleared') . '<br />';
}

/** Statistics have been counted since... */
$FE['Other-Since'] = empty($this->Loader->InstanceCache['Statistics']['Other-Since']) ? '-' : $this->Loader->timeFormat(
    $this->Loader->InstanceCache['Statistics']['Other-Since'],
    $this->Loader->Configuration['core']['time_format']
);

/** Fetch and process various statistics. */
foreach ([
    'Web-Events',
    'Web-Scanned',
    'Web-Blocked',
    'Web-Quarantined',
    'CLI-Events',
    'CLI-Scanned',
    'CLI-Flagged',
    'API-Events',
    'API-Scanned',
    'API-Flagged'
] as $TheseStats) {
    $FE[$TheseStats] = $this->NumberFormatter->format(
        $this->Loader->InstanceCache['Statistics'][$TheseStats] ?? 0
    );
}

/** Active signature files. */
if (empty($this->Loader->Configuration['signatures']['active'])) {
    $FE['Other-Active'] = $this->NumberFormatter->format(0);
    $FE['Class-Active'] = 'txtRd';
} else {
    $FE['Other-Active'] = \count(\array_unique(\array_filter(\explode(',', $this->Loader->Configuration['signatures']['active']), function ($Item) {
        return !empty($Item);
    })));
    $FE['Other-Active'] = $this->NumberFormatter->format($FE['Other-Active']);
    $FE['Class-Active'] = $FE['Other-Active'] ? 'txtGn' : 'txtRd';
}

/** Parse output. */
$FE['FE_Content'] = $this->Loader->parse($FE, $this->Loader->readFile($this->getAssetPath('_statistics.html')), true);

/** Send output. */
echo $this->sendOutput($FE);

/** Cleanup. */
unset($this->Loader->InstanceCache['Statistics']);

return;
