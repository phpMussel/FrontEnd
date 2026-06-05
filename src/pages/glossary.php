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
 * This file: Glossary for phpMussel (last modified: 2026.05.31).
 */

namespace phpMussel\FrontEnd;

if (!isset($Page) || $Page !== 'glossary' || ($this->Permissions !== 1 && $this->Permissions !== 2)) {
    die;
}

/** Page initial prepwork. */
$this->initialPrepwork($FE, $this->Loader->L10N->getString('link.Glossary'), $this->Loader->L10N->getString('tip.Glossary'));

/** Populate indexes. */
$FE['Indexes'] = [];
$Indexes = $this->Loader->L10N->Data['Glossary']['Indexes'] ?? (\is_array($this->Loader->L10N->Fallback) && isset($this->Loader->L10N->Fallback['Glossary']['Indexes']) ? $this->Loader->L10N->Fallback['Glossary']['Indexes'] : []);
foreach ($Indexes as $Index => $Anchor) {
    $FE['Indexes'][] = \sprintf('<a href="#%s">%s</a>', $Anchor, $Index);
}
\sort($FE['Indexes']);
$FE['Indexes'] = \implode("<br />\n      ", $FE['Indexes']);

/** Populate entries. */
$FE['Entries'] = [];
$Entries = $this->Loader->L10N->Data['Glossary']['Entries'] ?? (\is_array($this->Loader->L10N->Fallback) && isset($this->Loader->L10N->Fallback['Glossary']['Entries']) ? $this->Loader->L10N->Fallback['Glossary']['Entries'] : []);
$Refs = $this->Loader->L10N->Data['Glossary']['Refs'] ?? (\is_array($this->Loader->L10N->Fallback) && isset($this->Loader->L10N->Fallback['Glossary']['Refs']) ? $this->Loader->L10N->Fallback['Glossary']['Refs'] : []);
$SeeAlso = $this->Loader->L10N->getString('label.See also');
foreach ($Entries as $Index => $Entry) {
    if (\is_array($Entry)) {
        $Entry = $this->Loader->L10N->getString('Glossary.Entries.' . $Index);
    }
    if (empty($Entry)) {
        continue;
    }
    $Entry = \preg_replace('~(?<!\|)\n(?!\|)~', '<br /><br />', $Entry);

    /** Support for markdown-like tables. */
    if (\strpos($Entry, "\n| ") !== false) {
        $Entry = \preg_split('~\|\n\||(?<=\n)\||\|(?=\n)~', $Entry);
        $First = true;
        $RowOdd = true;
        foreach ($Entry as &$EntryPart) {
            if (($Count = \substr_count($EntryPart, '|')) === 0) {
                continue;
            }
            $Prepend = $First ? '        <div style="display:grid;margin:auto;grid-template-columns:' . \str_repeat('1fr ', $Count) . '1fr;text-align:center">' : '';
            $EntryPart = \explode('|', $EntryPart);
            $CellOdd = false;
            foreach ($EntryPart as &$Cell) {
                if ($Cell === '') {
                    continue;
                }
                $Style = 'gridboxitem s ' . ($CellOdd ? 'gridVB ' : 'gridVA ') . ($First ? 'configMatrixLabel' : ($RowOdd ? 'gridHB' : 'gridHA'));
                $Cell = '<div class="' . $Style . '">' . \trim($Cell, ' ') . '</div>';
                $CellOdd = !$CellOdd;
            }
            $EntryPart = $Prepend . \implode('', $EntryPart);
            $First = false;
            $RowOdd = !$RowOdd;
        }
        $Entry = \str_replace(["</div>\n", "\n"], ["</div></div>\n      ", "<br /><br />\n"], \implode('', $Entry));
    }

    /** Citations and references. */
    $Anchor = isset($Indexes[$Index]) ? ' id="' . $Indexes[$Index] . '"' : '';
    if (isset($Refs[$Index])) {
        $Entry .= '<br /><br />' . $SeeAlso . '<ul>';
        foreach ($Refs[$Index] as $RefName => $Ref) {
            $Entry .= \sprintf('<li><cite><a href="%s" dir="ltr" rel="noopener noreferrer external"><span class="navicon link"></span>%s</a></cite></li>', $Ref, $RefName);
        }
        $Entry .= '</ul>';
    }

    $FE['Entries'][] = \sprintf('<div class="ng1"><dl><dt%s>%s</dt><dd>%s</dd></dl></div>', $Anchor, $Index, $Entry);
}
foreach ($Refs as $Index => $Entry) {
    if (isset($Entries[$Index])) {
        continue;
    }
    $Anchor = isset($Indexes[$Index]) ? ' id="' . $Indexes[$Index] . '"' : '';
    $NewData = $SeeAlso . '<ul>';
    foreach ($Entry as $RefName => $Ref) {
        $NewData .= \sprintf('<li><cite><a href="%s" dir="ltr" rel="noopener noreferrer external"><span class="navicon link"></span>%s</a></cite></li>', $Ref, $RefName);
    }
    $NewData .= '</ul>';
    $FE['Entries'][] = \sprintf('<div class="ng1"><dl><dt%s>%s</dt><dd>%s</dd></dl></div>', $Anchor, $Index, $NewData);
}
\sort($FE['Entries']);
$FE['Entries'] = \implode("\n      ", $FE['Entries']);
unset($NewData, $Style, $Cell, $CellOdd, $Prepend, $Count, $EntryPart, $RowOdd, $First, $Ref, $RefName, $Entry, $SeeAlso, $Refs, $Entries, $Anchor, $Index, $Indexes);

/** Parse output. */
$FE['FE_Content'] = $this->Loader->parse($FE, $this->Loader->readFile($this->getAssetPath('_glossary.html')), true);

/** Send output. */
echo $this->sendOutput($FE);

return;
