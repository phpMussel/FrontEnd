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
 * This file: The signature information page (last modified: 2026.09.05).
 */

namespace phpMussel\FrontEnd;

if (!isset($Page) || $Page !== 'siginfo' || empty($this->PermissionsMap['Signature Information'])) {
    die;
}

/** Page initial prepwork. */
$this->initialPrepwork($FE, $this->Loader->L10N->getString('link.Signature Information'), $this->Loader->L10N->getString('tip.Signature Information'));

/** Append number localisation JS. */
$FE['JS'] .= $this->numberJs() . "\n";

$FE['SigInfoMenuOptions'] = '';

/** Process signature files and fetch relevant values. */
if (!$this->Loader->loadShorthandData()) {
    $FE['InfoRows'] = '      <span class="s">' . $this->Loader->L10N->getString('response.Error') . "</span>\n";
} else {
    $FE['InfoRows'] = '';

    /** Template for range rows. */
    $InfoRow = $this->Loader->readFile($this->getAssetPath('_siginfo_row.html'));

    /** Get list of vendor search patterns and metadata search pattern partials. */
    $Arr = [
        'Vendors' => $this->Loader->InstanceCache['shorthand.yml']['Vendor Search Patterns'],
        'SigTypes' => $this->Loader->InstanceCache['shorthand.yml']['Metadata Search Pattern Partials']
    ];

    /** Expand patterns for signature metadata. */
    foreach ($Arr['SigTypes'] as &$Arr['Type']) {
        $Arr['Type'] = \sprintf('\x1A(?![\x80-\x8F])[\x0%1$s\x1%1$s\x2%1$s\x3%1$s\x4%1$s\x5%1$s\x6%1$s\x7%1$s\x8%1$s\x9%1$s\xa%1$s\xb%1$s\xc%1$s\xd%1$s\xe%1$s\ef%1$s].', $Arr['Type']);
    }

    /** Get list of vector search patterns. */
    $Arr['Targets'] = $this->Loader->InstanceCache['shorthand.yml']['Vector Search Patterns'];

    /** Get list of malware type search patterns. */
    $Arr['MalwareTypes'] = $this->Loader->InstanceCache['shorthand.yml']['Malware Type Search Patterns'];

    /** To be populated by totals. */
    $Totals = ['Classes' => [], 'Files' => [], 'Vendors' => [], 'SigTypes' => [], 'Targets' => [], 'MalwareTypes' => []];

    /** Signature file classes. */
    $Classes = [
        ['General_Command_Detections', ''],
        ['Filename', '\n(?!>)'],
        ['Hash', '\n[\dA-Fa-f]{32,}:\d+:'],
        ['Standard', '\n(?!>)'],
        ['Standard_RegEx', '\n(?!>)'],
        ['Normalised', '\n(?!>)'],
        ['Normalised_RegEx', '\n(?!>)'],
        ['HTML', '\n(?!>)'],
        ['HTML_RegEx', '\n(?!>)'],
        ['PE_Extended', '\n\$PE\w+:[\dA-Fa-f]{32,}:\d+:'],
        ['PE_Sectional', '\n\d+:[\dA-Fa-f]{32,}:'],
        ['Complex_Extended', '\n\$\S+;'],
        ['URL_Scanner', '\n(?:TLD|(?:DOMAIN|URL)(?:-NOLOOKUP)?|QUERY)\S+:']
    ];

    /** We cycle through this several times in this closure. */
    $Subs = ['Classes', 'Files', 'Vendors', 'SigTypes', 'Targets', 'MalwareTypes'];

    /** The currently active signature files. */
    $Active = \array_unique(\array_filter(\explode(',', $this->Loader->Configuration['signatures']['active']), function ($Item) {
        return !empty($Item);
    }));

    /** Iterate through active signature files and append totals. */
    foreach ($Active as $File) {
        $File = (\strpos($File, ':') === false) ? $File : \substr($File, \strpos($File, ':') + 1);
        if ($File === '' || $this->Loader->isReserved($File)) {
            continue;
        }
        $Data = $this->Loader->readFile($this->Loader->SignaturesPath . $File);
        if (\substr($Data, 0, 9) !== 'phpMussel') {
            continue;
        }
        $Class = \substr($Data, 9, 1);
        $Nibbles = \strlen($Class) ? $this->Scanner->splitNibble($Class) : [-1, -1];
        $Class = $Classes[$Nibbles[0]] ?? [];
        $Totals['Files'][$File] = empty($Class[1]) ? 0 : \preg_match_all('/' . $Class[1] . '\S+/', $Data);
        if (isset($Class[1])) {
            $Totals['Classes'][$Class[0]] = isset($Totals['Classes'][$Class[0]]) ? $Totals['Classes'][$Class[0]] + $Totals['Files'][$File] : $Totals['Files'][$File];
        }
        foreach ($Subs as $Sub) {
            $Totals[$Sub]['Total'] = isset($Totals[$Sub]['Total']) ? $Totals[$Sub]['Total'] + $Totals['Files'][$File] : $Totals['Files'][$File];
        }
        $this->normaliseLinebreaks($Data);
        if (!empty($Class[1])) {
            foreach (['Vendors', 'SigTypes', 'Targets', 'MalwareTypes'] as $Sub) {
                foreach ($Arr[$Sub] as $Key => $Pattern) {
                    $Counts = \preg_match_all('/' . $Class[1] . '(?:' . $Pattern . ')\S+/', $Data);
                    $Totals[$Sub][$Key] = isset($Totals[$Sub][$Key]) ? $Totals[$Sub][$Key] + $Counts : $Counts;
                }
            }
        }
    }

    /** Build "other" totals. */
    foreach ($Subs as $Sub) {
        $Other = $Totals[$Sub]['Total'] ?? 0;
        foreach ($Totals[$Sub] as $Key => $SubTotal) {
            if ($Key === 'Total') {
                continue;
            }
            $Other -= $SubTotal;
        }
        $Totals[$Sub]['Other'] = $Other;
    }

    /** Cleanup. */
    unset($SubTotal, $Other, $Data, $Nibbles, $Active, $File, $Counts, $Arr);

    /** Process totals. */
    foreach ($Subs as $Sub) {
        $Label = $this->Loader->L10N->getString('Signature information.sub_' . $Sub) ?: $Sub;
        $Class = 'sigtype_' . \strtolower($Sub);
        $FE['SigInfoMenuOptions'] .= "\n          <option value=\"" . $Class . '">' . $Label . '</option>';
        $FE['InfoRows'] .= '      <div class="center h2f s flexstretch ' . $Class . '" style="display:none">' . $Label . "</div>\n      <div class=\"duo flexstretch " . $Class . "_grid\" style=\"display:none\">\n";
        \arsort($Totals[$Sub]);
        foreach ($Totals[$Sub] as $Key => &$Total) {
            if (!$Total) {
                continue;
            }
            $Total = $this->NumberFormatter->format($Total);
            $Label = $this->Loader->L10N->getString(
                ($Key === 'Other' && $Sub === 'SigTypes') ? 'Signature information.key_Other_Metadata' : 'Signature information.key_' . $Key
            );
            if ($Key !== 'Total' && $Key !== 'Other') {
                if (!$Label) {
                    $Label = \sprintf($this->Loader->L10N->getString('Signature information.xkey'), $Key);
                }
                $CellClass = 'h1';
            } else {
                $CellClass = 'r';
            }
            $FE['InfoRows'] .= $this->Loader->parse(['CellClass' => $CellClass, 'InfoType' => $Label, 'InfoNum' => $Total], $InfoRow);
        }
        $FE['InfoRows'] .= "      </div>\n";
    }

    /** Cleanup. */
    unset($CellClass, $Key, $Label, $Class, $Sub, $Subs);
}

/** Calculate and append page load time, and append totals. */
$FE['ProcTime'] = \microtime(true) - $_SERVER['REQUEST_TIME_FLOAT'];
$FE['ProcTime'] = \sprintf(
    $this->Loader->L10N->getPlural($FE['ProcTime'], 'label.Page request completed in %s seconds'),
    '<span class="txtRd">' . $this->NumberFormatter->format($FE['ProcTime'], 3) . '</span>'
);

/** Parse output. */
$FE['FE_Content'] = $this->Loader->parse($FE, $this->Loader->readFile($this->getAssetPath('_siginfo.html')), true);

/** Send output. */
echo $this->sendOutput($FE);

return;
