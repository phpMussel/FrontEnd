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
 * This file: The signature information page (last modified: 2023.12.29).
 */

namespace phpMussel\FrontEnd;

if (!isset($Page) || $Page !== 'siginfo' || $this->Permissions !== 1) {
    die;
}

/** Page initial prepwork. */
$this->initialPrepwork($FE, $this->Loader->L10N->getString('link.Signature Information'), $this->Loader->L10N->getString('tip.Signature Information'));

/** Append number localisation JS. */
$FE['JS'] .= $this->numberJs() . "\n";

$FE['InfoRows'] = '';
$FE['SigInfoMenuOptions'] = '';

/** Process signature files and fetch relevant values. */
$this->signatureInformationHandler($FE['InfoRows'], $FE['SigInfoMenuOptions']);

/** Calculate and append page load time, and append totals. */
$FE['ProcTime'] = microtime(true) - $_SERVER['REQUEST_TIME_FLOAT'];
$FE['ProcTime'] = '<div class="s">' . sprintf(
    $this->Loader->L10N->getPlural($FE['ProcTime'], 'label.Page request completed in %s seconds'),
    '<span class="txtRd">' . $this->NumberFormatter->format($FE['ProcTime'], 3) . '</span>'
) . '</div>';

/** Parse output. */
$FE['FE_Content'] = $this->Loader->parse($FE, $this->Loader->readFile($this->getAssetPath('_siginfo.html')), true);

/** Send output. */
echo $this->sendOutput($FE);

return;
