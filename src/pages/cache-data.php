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
 * This file: The cache data page (last modified: 2026.03.22).
 */

namespace phpMussel\FrontEnd;

if (!isset($Page) || $Page !== 'cache-data' || $this->Permissions !== 1) {
    die;
}

/** Page initial prepwork. */
$this->initialPrepwork($FE, $this->Loader->L10N->getString('link.Cache Data'), $this->Loader->L10N->getString('tip.Cache Data'));

/** All cache sources. */
$Sources = [];

/** The primary caching source. */
if ($this->Loader->Cache->Using !== '') {
    $Sources[$this->Loader->Cache->Using] = &$this->Loader->Cache;
}

/** In case a flatfile cache exists but isn't the primary caching source. */
if ($this->Loader->Cache->Using !== 'FF' && $this->Loader->CachePath !== '' && \is_writable($this->Loader->CachePath)) {
    $Sources['FF'] = new \Maikuolan\Common\Cache();
    $Sources['FF']->Prefix = $this->Loader->Configuration['supplementary_cache_options']['prefix'];
    $Sources['FF']->FFDefault = $this->Loader->Cache->FFDefault;
    if (!$Sources['FF']->connect()) {
        $Sources['FF'] = false;
    }
}

/**
 * In case APCu is available but isn't the primary caching source (doing this
 * for APCu but not the others, as the others would potentially require a
 * server connection, which may or may not be desirable to the user, whereas
 * APCu data should be immediately available if the extension is available at
 * all).
 */
if ($this->Loader->Cache->Using !== 'APCu' && \extension_loaded('apcu')) {
    $Sources['APCu'] = new \Maikuolan\Common\Cache();
    $Sources['APCu']->Prefix = $this->Loader->Configuration['supplementary_cache_options']['prefix'];
    $Sources['APCu']->EnableAPCu = true;
    if (!$Sources['APCu']->connect()) {
        $Sources['APCu'] = false;
    }
}

if ($FE['ASYNC']) {
    if (isset($_POST['do'])) {
        /** Delete a cache entry. */
        if ($_POST['do'] === 'delete' && isset($_POST['cdi'], $_POST['csrc']) && $_POST['cdi'] !== '' && $_POST['csrc'] !== '' && isset($Sources[$_POST['csrc']])) {
            if ($_POST['cdi'] === '__') {
                /** Delete all entries ("clear all"). */
                $Sources[$_POST['csrc']]->clearCache();
            } elseif (\substr($_POST['cdi'], 0, 1) === '^') {
                /** Delete all sub-entries under a specific parent entry. */
                $Sources[$_POST['csrc']]->deleteAllEntriesWhere('~' . $_POST['cdi'] . '-~');
            } else {
                /** Delete just a specific entry (or sub-entry). */
                $Sources[$_POST['csrc']]->deleteEntry($_POST['cdi']);
            }
        }

        /** Duplicate cache entries. */
        if ($_POST['do'] === 'duplicate' && isset($_POST['csrc'], $_POST['ctrg']) && $_POST['csrc'] !== '' && $_POST['ctrg'] !== '' && isset($Sources[$_POST['csrc']], $Sources[$_POST['ctrg']])) {
            $Sources[$_POST['ctrg']]->setEntries($Sources[$_POST['csrc']]->getAllEntries());
        }
    }
} else {
    /** Append async globals. */
    $FE['JS'] .=
        "function cdd(d,x){window.cdi=d,window.csrc=x,window.do='delete',$('POST" .
        "','',['cidram-form-target','cdi','csrc','do'],null,function(o){'__'===d" .
        "?window.location.reload():'^'===d.substring(0,1)&&(d=d.substr(1)),hidei" .
        "d(d+'Container'+x)})};function cdp(d,x){window.csrc=d,window.ctrg=x,win" .
        "dow.do='duplicate',$('POST','',['cidram-form-target','csrc','ctrg','do'" .
        "],null,function(o){window.location.reload()})}window['cidram-form-targe" .
        "t']='cache-data';";

    /** To be populated by the cache data. */
    $FE['CacheData'] = '';

    $IsFirst = true;
    $ClearAll = $this->Loader->L10N->getString('field.Clear all');
    $Action = $this->Loader->L10N->getString('confirm.Action');
    $Duplicate = $this->Loader->L10N->getString('label.Duplicate to %s');
    foreach ($Sources as $SourceKey => &$Source) {
        $CacheArray = [];
        foreach ($Source->getAllEntries() as $ThisCacheName => $ThisCacheItem) {
            if (isset($ThisCacheItem['Time']) && $ThisCacheItem['Time'] > 0 && $ThisCacheItem['Time'] < $this->Loader->Time) {
                continue;
            }
            $this->Loader->arrayify($ThisCacheItem);
            $CacheArray[$ThisCacheName] = $ThisCacheItem;
        }
        if (!$IsFirst && \count($CacheArray) === 0) {
            continue;
        }

        /** Source label. */
        $SourceLabel = $SourceKey === 'FF' ? \preg_replace('~^.*[\\\\/]([^\\\\/]+)$~', '\1', $Source->FFDefault) : $SourceKey;

        /** Whether inactive. */
        $Status = $IsFirst ? '' : ' (' . $this->Loader->L10N->getString('label.Inactive') . ')';

        /** Duplicability. */
        $Duplicability = '';
        foreach (\array_keys($Sources) as $Key) {
            if ($Key === $SourceKey) {
                continue;
            }
            $KeyLabel = $Key === 'FF' ? 'cache.dat' : $Key;
            $DuplicateTo = \sprintf($Duplicate, $KeyLabel);
            $Duplicability .= ' – <span onclick="javascript:confirm(\'' . \str_replace(
                ["'", '"'],
                ["\'", '\x22'],
                \sprintf($Action, \sprintf($Duplicate, $KeyLabel))
            ) . '\')&&cdp(\'' . $SourceKey . '\',\'' . $Key . '\')"><code><span class="smicon export" title="' . $DuplicateTo . '"></span><span class="s smicontxt">' . $DuplicateTo . '</span></code></span>';
        }

        /** Process all cache items. */
        $FE['CacheData'] .= \sprintf(
            '<div class="ng1" id="__Container%1$s"><span class="s">%2$s – (<span onclick="javascript:confirm(\'%3$s\')&&cdd(\'__\',\'%1$s\')"><code><span class="smicon red delete" title="%4$s"></span><span class="s smicontxt">%4$s</span></code></span>%5$s)</span><br /><br /><ul class="pieul">%6$s</ul></div>',
            $SourceKey,
            $SourceLabel . $Status,
            \str_replace(["'", '"'], ["\'", '\x22'], \sprintf($Action, $ClearAll) . ($IsFirst ? '\n' . $this->Loader->L10N->getString('warning.Proceeding will log out all users') : '')),
            $ClearAll,
            $Duplicability,
            $this->arrayToClickableList($CacheArray, 'cdd', 0, $SourceLabel, $SourceKey)
        );
        $IsFirst = false;
    }
    unset($DuplicateTo, $KeyLabel, $Key, $Duplicability, $Status, $SourceLabel, $ThisCacheName, $ThisCacheItem, $CacheArray, $Source, $SourceKey, $Duplicate, $Action, $ClearAll, $IsFirst);

    /** Cache is empty. */
    if (!$FE['CacheData']) {
        $FE['CacheData'] = '<div class="ng1"><span class="s">' . $this->Loader->L10N->getString('label.The cache is empty') . '</span></div>';
    }

    /** Parse output. */
    $FE['FE_Content'] = $this->Loader->parse($FE, $this->Loader->readFile($this->getAssetPath('_cache.html')), true) . $MenuToggle;

    /** Send output. */
    echo $this->sendOutput($FE);
}
unset($Sources);
return;
