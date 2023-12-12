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
 * This file: The cache data page (last modified: 2023.12.12).
 */

if (!isset($Page) || $Page !== 'cache-data' || $this->Permissions !== 1) {
    die;
}

/** Page initial prepwork. */
$this->initialPrepwork($FE, $this->Loader->L10N->getString('link.Cache Data'), $this->Loader->L10N->getString('tip.Cache Data'));

if ($FE['ASYNC']) {
    /** Delete a cache entry. */
    if (isset($_POST['do']) && $_POST['do'] === 'delete' && !empty($_POST['cdi'])) {
        if ($_POST['cdi'] === '__') {
            $this->Loader->Cache->clearCache();
        } else {
            $this->Loader->Cache->deleteEntry($_POST['cdi']);
        }
    }
} else {
    /** Append async globals. */
    $FE['JS'] .=
        "function cdd(d){window.cdi=d,window.do='delete',$('POST','',['phpmussel-" .
        "form-target','cdi','do'],null,function(o){'__'===d?window.location=windo" .
        "w.location.href.split('?')[0]:hideid(d+'Container')})}window['phpmussel-" .
        "form-target']='cache-data';";

    /** To be populated by the cache data. */
    $FE['CacheData'] = '';

    /** Get cache index data and process all cache items. */
    if ($this->Loader->Cache->Using) {
        /** Array of all cache items. */
        $CacheArray = [];

        /** Get cache index data. */
        foreach ($this->Loader->Cache->getAllEntries() as $ThisCacheName => $ThisCacheItem) {
            if (isset($ThisCacheItem['Time']) && $ThisCacheItem['Time'] > 0 && $ThisCacheItem['Time'] < $this->Loader->Time) {
                continue;
            }
            $this->Loader->arrayify($ThisCacheItem);
            $CacheArray[$ThisCacheName] = $ThisCacheItem;
        }
        unset($ThisCacheName, $ThisCacheItem);

        /** Process all cache items. */
        $FE['CacheData'] .= sprintf(
            '<div class="ng1" id="__Container"><span class="s">%s – (<span style="cursor:pointer" onclick="javascript:confirm(\'%s\')&&cdd(\'__\')"><code class="s">%s</code></span>)</span><br /><br /><ul class="pieul">%s</ul></div>',
            $this->Loader->Cache->Using,
            str_replace(["'", '"'], ["\'", '\x22'], sprintf(
                $this->Loader->L10N->getString('confirm.Action'),
                $this->Loader->L10N->getString('field.Clear all')
            ) . '\n' . $this->Loader->L10N->getString('warning.Proceeding will log out all users')),
            $this->Loader->L10N->getString('field.Clear all'),
            $this->arrayToClickableList($CacheArray, 'cdd', 0, $this->Loader->Cache->Using)
        );
        unset($CacheArray);
    }

    /** Cache is empty. */
    if (!$FE['CacheData']) {
        $FE['CacheData'] = '<div class="ng1"><span class="s">' . $this->Loader->L10N->getString('label.The cache is empty') . '</span></div>';
    }

    /** Parse output. */
    $FE['FE_Content'] = $this->Loader->parse($FE, $this->Loader->readFile($this->getAssetPath('_cache.html')), true) . $MenuToggle;

    /** Send output. */
    echo $this->sendOutput($FE);
}

return;
