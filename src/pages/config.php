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
 * This file: The configuration page (last modified: 2023.12.12).
 */

if (!isset($Page) || $Page !== 'config' || $this->Permissions !== 1) {
    die;
}

/** Page initial prepwork. */
$this->initialPrepwork($FE, $this->Loader->L10N->getString('link.Configuration'), $this->Loader->L10N->getString('tip.Configuration'));

/** Append number localisation JS. */
$FE['JS'] .= $this->numberJS() . "\n";

/** Directive template. */
$ConfigurationRow = $this->Loader->readFile($this->getAssetPath('_config_row.html'));

/** Flag for modified configuration. */
$ConfigurationModified = false;

$FE['Indexes'] = '<ul class="pieul">';
$FE['ConfigFields'] = '';

/** For required extensions, classes, etc. */
$ReqsLookupCache = [];

/** Rebuilding in order to strip out orphaned data. */
if (isset($_POST['orphaned'])) {
    $NewConfig = [];
}

/** Iterate through configuration defaults. */
foreach ($this->Loader->ConfigurationDefaults as $CatKey => $CatValue) {
    if (!is_array($CatValue)) {
        continue;
    }
    if ($CatInfo = $this->Loader->L10N->getString('config.' . $CatKey)) {
        $CatInfo = '<br /><em>' . $CatInfo . '</em>';
    }
    $FE['ConfigFields'] .= sprintf(
        '<table class="tablend"><tr><td class="ng2"><div id="%1$s-container" class="s">' .
        '<a id="%1$sShowLink" class="showlink" href="#%1$s-container" onclick="javascript:toggleconfig(\'%1$sRow\',\'%1$sShowLink\')">%1$s</a>' .
        '%3$s</div></td></tr></table><span id="%1$sRow" %2$s><table class="tablend">',
        $CatKey,
        'style="display:none"',
        $CatInfo
    ) . "\n";
    $CatData = '';
    foreach ($CatValue as $DirKey => $DirValue) {
        $ThisDir = ['Reset' => '', 'Preview' => '', 'Trigger' => '', 'FieldOut' => '', 'CatKey' => $CatKey];
        if (empty($DirValue['type']) || !isset($this->Loader->Configuration[$CatKey][$DirKey])) {
            continue;
        }
        $ThisDir['DirLangKey'] = 'config_' . $CatKey . '_' . $DirKey;
        $ThisDir['DirLangKeyOther'] = $ThisDir['DirLangKey'] . '_other';
        $ThisDir['DirName'] = '<span class="normalHeight">' . $this->ltrInRtf($CatKey . '➡' . $DirKey) . ':</span>';
        $ThisDir['Friendly'] = $this->Loader->L10N->getString('config.' . $CatKey . '_' . $DirKey . '_label') ?: $DirKey;
        $CatData .= sprintf(
            '<li><a onclick="javascript:toggleconfigNav(\'%1$sRow\',\'%1$sShowLink\')" href="#%2$s">%3$s</a></li>',
            $CatKey,
            $ThisDir['DirLangKey'],
            $ThisDir['Friendly']
        );
        $ThisDir['DirLang'] =
            $this->Loader->L10N->getString('config.' . $CatKey . '_' . $DirKey) ?:
            $this->Loader->L10N->getString('label.' . $DirKey) ?:
            $this->Loader->L10N->getString('config.' . $CatKey) ?:
            $this->Loader->L10N->getString('response.Error');
        if (!empty($DirValue['experimental'])) {
            $ThisDir['DirLang'] = '<code class="exp">' . $this->Loader->L10N->getString('config.experimental') . '</code> ' . $ThisDir['DirLang'];
        }
        $ThisDir['autocomplete'] = empty($DirValue['autocomplete']) ? '' : sprintf(
            ' autocomplete="%s"',
            $DirValue['autocomplete']
        );

        /** Fix for PHP automatically changing certain kinds of $_POST keys. */
        if (!isset($_POST[$ThisDir['DirLangKey']])) {
            $Try = str_replace('.', '_', $ThisDir['DirLangKey']);
            if (isset($_POST[$Try])) {
                $_POST[$ThisDir['DirLangKey']] = $_POST[$Try];
                unset($_POST[$Try]);
            }
        }

        if (isset($_POST[$ThisDir['DirLangKey']])) {
            if (in_array($DirValue['type'], ['bool', 'float', 'int', 'kb', 'string', 'timezone', 'email', 'url'], true)) {
                $this->Loader->autoType($_POST[$ThisDir['DirLangKey']], $DirValue['type']);
            }
            if (!isset($DirValue['choices']) || isset($DirValue['choices'][$_POST[$ThisDir['DirLangKey']]])) {
                $ConfigurationModified = true;
                $this->Loader->Configuration[$CatKey][$DirKey] = $_POST[$ThisDir['DirLangKey']];
            } elseif (
                !empty($DirValue['allow_other']) &&
                $_POST[$ThisDir['DirLangKey']] === 'Other' &&
                isset($_POST[$ThisDir['DirLangKeyOther']]) &&
                !preg_match('/[^\x20-\xFF"\']/', $_POST[$ThisDir['DirLangKeyOther']])
            ) {
                $ConfigurationModified = true;
                $this->Loader->Configuration[$CatKey][$DirKey] = $_POST[$ThisDir['DirLangKeyOther']];
            }
        } elseif (
            $DirValue['type'] === 'checkbox' &&
            isset($DirValue['choices']) &&
            is_array($DirValue['choices'])
        ) {
            $DirValue['Posts'] = [];
            foreach ($DirValue['choices'] as $DirValue['ThisChoiceKey'] => $DirValue['ThisChoice']) {
                if (isset($DirValue['labels']) && is_array($DirValue['labels'])) {
                    foreach ($DirValue['labels'] as $DirValue['ThisLabelKey'] => $DirValue['ThisLabel']) {
                        if (!empty($_POST[$ThisDir['DirLangKey'] . '_' . $DirValue['ThisChoiceKey'] . '_' . $DirValue['ThisLabelKey']])) {
                            $DirValue['Posts'][] = $DirValue['ThisChoiceKey'] . ':' . $DirValue['ThisLabelKey'];
                        } else {
                            $Try = str_replace('.', '_', $ThisDir['DirLangKey'] . '_' . $DirValue['ThisChoiceKey'] . '_' . $DirValue['ThisLabelKey']);
                            if (!empty($_POST[$Try])) {
                                $_POST[$ThisDir['DirLangKey'] . '_' . $DirValue['ThisChoiceKey'] . '_' . $DirValue['ThisLabelKey']] = $_POST[$Try];
                                unset($_POST[$Try]);
                                $DirValue['Posts'][] = $DirValue['ThisChoiceKey'] . ':' . $DirValue['ThisLabelKey'];
                            }
                        }
                    }
                } elseif (!empty($_POST[$ThisDir['DirLangKey'] . '_' . $DirValue['ThisChoiceKey']])) {
                    $DirValue['Posts'][] = $DirValue['ThisChoiceKey'];
                } else {
                    $Try = str_replace('.', '_', $ThisDir['DirLangKey'] . '_' . $DirValue['ThisChoiceKey']);
                    if (!empty($_POST[$Try])) {
                        $_POST[$ThisDir['DirLangKey'] . '_' . $DirValue['ThisChoiceKey']] = $_POST[$Try];
                        unset($_POST[$Try]);
                        $DirValue['Posts'][] = $DirValue['ThisChoiceKey'];
                    }
                }
            }
            $DirValue['Posts'] = implode(',', $DirValue['Posts']) ?: '';
            if (!empty($_POST['updatingConfig']) && $this->Loader->Configuration[$CatKey][$DirKey] !== $DirValue['Posts']) {
                $ConfigurationModified = true;
                $this->Loader->Configuration[$CatKey][$DirKey] = $DirValue['Posts'];
            }
        }
        if (isset($DirValue['preview'])) {
            $ThisDir['Preview'] = ($DirValue['preview'] === 'allow_other') ? '' : sprintf(' = <span id="%s_preview"></span>', $ThisDir['DirLangKey']);
            $ThisDir['Trigger'] = ' onchange="javascript:' . $ThisDir['DirLangKey'] . '_function();" onkeyup="javascript:' . $ThisDir['DirLangKey'] . '_function();"';
            if ($DirValue['preview'] === 'seconds') {
                $ThisDir['Preview'] .= sprintf(
                    '<script type="text/javascript">function %1$s_function(){var t=%9$s?%9$s(' .
                    '\'%1$s_field\').value:%10$s&&!%9$s?%10$s.%1$s_field.value:\'\',e=isNaN(t' .
                    ')?0:0>t?t*-1:t,n=e?Math.floor(e/31536e3):0,e=e?e-31536e3*n:0,o=e?Math.fl' .
                    'oor(e/2592e3):0,e=e-2592e3*o,l=e?Math.floor(e/604800):0,e=e-604800*l,r=e' .
                    '?Math.floor(e/86400):0,e=e-86400*r,d=e?Math.floor(e/3600):0,e=e-3600*d,i' .
                    '=e?Math.floor(e/60):0,e=e-60*i,f=e?Math.floor(1*e):0,a=nft(n.toString())' .
                    '+\' %2$s – \'+nft(o.toString())+\' %3$s – \'+nft(l.toString())+\' %4$s –' .
                    ' \'+nft(r.toString())+\' %5$s – \'+nft(d.toString())+\' %6$s – \'+nft(i.' .
                    'toString())+\' %7$s – \'+nft(f.toString())+\' %8$s\';%9$s?%9$s(\'%1$s_pr' .
                    'eview\').innerHTML=a:%10$s&&!%9$s?%10$s.%1$s_preview.innerHTML=a:\'\'}' .
                    '%1$s_function();</script>',
                    $ThisDir['DirLangKey'],
                    $this->Loader->L10N->getString('previewer.Years'),
                    $this->Loader->L10N->getString('previewer.Months'),
                    $this->Loader->L10N->getString('previewer.Weeks'),
                    $this->Loader->L10N->getString('previewer.Days'),
                    $this->Loader->L10N->getString('previewer.Hours'),
                    $this->Loader->L10N->getString('previewer.Minutes'),
                    $this->Loader->L10N->getString('previewer.Seconds'),
                    'document.getElementById',
                    'document.all'
                );
            } elseif ($DirValue['preview'] === 'minutes') {
                $ThisDir['Preview'] .= sprintf(
                    '<script type="text/javascript">function %1$s_function(){var t=%9$s?%9$s(' .
                    '\'%1$s_field\').value:%10$s&&!%9$s?%10$s.%1$s_field.value:\'\',e=isNaN(t' .
                    ')?0:0>t?t*-1:t,n=e?Math.floor(e/525600):0,e=e?e-525600*n:0,o=e?Math.floo' .
                    'r(e/43200):0,e=e-43200*o,l=e?Math.floor(e/10080):0,e=e-10080*l,r=e?Math.' .
                    'floor(e/1440):0,e=e-1440*r,d=e?Math.floor(e/60):0,e=e-60*d,i=e?Math.floo' .
                    'r(e*1):0,e=e-i,f=e?Math.floor(60*e):0,a=nft(n.toString())+\' %2$s – \'+n' .
                    'ft(o.toString())+\' %3$s – \'+nft(l.toString())+\' %4$s – \'+nft(r.toStr' .
                    'ing())+\' %5$s – \'+nft(d.toString())+\' %6$s – \'+nft(i.toString())+\' ' .
                    '%7$s – \'+nft(f.toString())+\' %8$s\';%9$s?%9$s(\'%1$s_preview\').innerH' .
                    'TML=a:%10$s&&!%9$s?%10$s.%1$s_preview.innerHTML=a:\'\'}%1$s_function();<' .
                    '/script>',
                    $ThisDir['DirLangKey'],
                    $this->Loader->L10N->getString('previewer.Years'),
                    $this->Loader->L10N->getString('previewer.Months'),
                    $this->Loader->L10N->getString('previewer.Weeks'),
                    $this->Loader->L10N->getString('previewer.Days'),
                    $this->Loader->L10N->getString('previewer.Hours'),
                    $this->Loader->L10N->getString('previewer.Minutes'),
                    $this->Loader->L10N->getString('previewer.Seconds'),
                    'document.getElementById',
                    'document.all'
                );
            } elseif ($DirValue['preview'] === 'hours') {
                $ThisDir['Preview'] .= sprintf(
                    '<script type="text/javascript">function %1$s_function(){var t=%9$s?%9$s(' .
                    '\'%1$s_field\').value:%10$s&&!%9$s?%10$s.%1$s_field.value:\'\',e=isNaN(t' .
                    ')?0:0>t?t*-1:t,n=e?Math.floor(e/8760):0,e=e?e-8760*n:0,o=e?Math.floor(e/' .
                    '720):0,e=e-720*o,l=e?Math.floor(e/168):0,e=e-168*l,r=e?Math.floor(e/24):' .
                    '0,e=e-24*r,d=e?Math.floor(e*1):0,e=e-d,i=e?Math.floor(60*e):0,e=e-(i/60)' .
                    ',f=e?Math.floor(3600*e):0,a=nft(n.toString())+\' %2$s – \'+nft(o.toStrin' .
                    'g())+\' %3$s – \'+nft(l.toString())+\' %4$s – \'+nft(r.toString())+\' ' .
                    '%5$s – \'+nft(d.toString())+\' %6$s – \'+nft(i.toString())+\' %7$s – \'+' .
                    'nft(f.toString())+\' %8$s\';%9$s?%9$s(\'%1$s_preview\').innerHTML=a:' .
                    '%10$s&&!%9$s?%10$s.%1$s_preview.innerHTML=a:\'\'}%1$s_function();</script>',
                    $ThisDir['DirLangKey'],
                    $this->Loader->L10N->getString('previewer.Years'),
                    $this->Loader->L10N->getString('previewer.Months'),
                    $this->Loader->L10N->getString('previewer.Weeks'),
                    $this->Loader->L10N->getString('previewer.Days'),
                    $this->Loader->L10N->getString('previewer.Hours'),
                    $this->Loader->L10N->getString('previewer.Minutes'),
                    $this->Loader->L10N->getString('previewer.Seconds'),
                    'document.getElementById',
                    'document.all'
                );
            } elseif ($DirValue['preview'] === 'allow_other') {
                $ThisDir['Preview'] .= sprintf(
                    '<script type="text/javascript">function %1$s_function(){var e=%2$s?%2$s(' .
                    '\'%1$s_field\').value:%3$s&&!%2$s?%3$s.%1$s_field.value:\'\';e==\'Other\'' .
                    '?showid(\'%4$s_field\'):hideid(\'%4$s_field\')};%1$s_function();</script>',
                    $ThisDir['DirLangKey'],
                    'document.getElementById',
                    'document.all',
                    $ThisDir['DirLangKeyOther']
                );
            } elseif (substr($DirValue['preview'], 0, 3) === 'js:') {
                $ThisDir['Preview'] .= '<script type="text/javascript">' . sprintf(
                    substr($DirValue['preview'], 3),
                    $ThisDir['DirLangKey']
                ) . '</script>';
            }
        } elseif ($DirValue['type'] === 'kb') {
            $ThisDir['Preview'] = sprintf(' = <span id="%s_preview"></span>', $ThisDir['DirLangKey']);
            $ThisDir['Trigger'] = ' onchange="javascript:' . $ThisDir['DirLangKey'] . '_function();" onkeyup="javascript:' . $ThisDir['DirLangKey'] . '_function();"';
            $ThisDir['Preview'] .= sprintf(
                '<script type="text/javascript">function %1$s_function(){const bytesPerUnit={' .
                'B:1,K:1024,M:1048576,G:1073741824,T:1099511627776,P:1125899906842620},unitNa' .
                'mes=["%2$s","%3$s","%4$s","%5$s","%6$s","%7$s"];var e=%8$s?%8$s(\'%1$s_field' .
                '\').value:%9$s&&!%8$s?%9$s.%1$s_field.value:\'\';if((Unit=e.match(/(?<Unit>[' .
                'KkMmGgTtPpOoBb]|К|к|М|м|Г|г|Т|т|П|п|Ｋ|ｋ|Ｍ|ｍ|Ｇ|ｇ|Ｔ|ｔ|Ｐ|ｐ|Б|б|Ｂ|ｂ)(?:[OoBb]|Б|' .
                'б|Ｂ|ｂ)?$/))&&void 0!==Unit.groups.Unit)if((Unit=Unit.groups.Unit).match(/^(?' .
                ':[OoBb]|Б|б|Ｂ|ｂ)$/))var Unit=\'B\';else if(Unit.match(/^(?:[Mm]|М|м)$/))Unit' .
                '=\'M\';else if(Unit.match(/^(?:[Gg]|Г|г)$/))Unit=\'G\';else if(Unit.match(/^' .
                '(?:[Tt]|Т|т)$/))Unit=\'T\';else if(Unit.match(/^(?:[Pp]|П|п)$/))Unit=\'P\';e' .
                'lse Unit=\'K\';else Unit=\'K\';var e=parseFloat(e);if(isNaN(e))var fixed=0;e' .
                'lse{if(void 0!==bytesPerUnit[Unit])fixed=e*bytesPerUnit[Unit];else fixed=e;f' .
                'ixed=Math.floor(fixed)}for(var i=0,p=unitNames[i];fixed>=1024;){fixed=fixed/' .
                '1024;i++;p=unitNames[i];if(i>=5)break}t=nft(fixed.toFixed(i===0?0:2))+\' \'+' .
                'p;%8$s?%8$s(\'%1$s_preview\').innerHTML=t:%9$s&&!%8$s?%9$s.%1$s_preview.inne' .
                'rHTML=t:\'\';};%1$s_function();</script>',
                $ThisDir['DirLangKey'],
                $this->Loader->L10N->getPlural(0, 'field.size.bytes'),
                $this->Loader->L10N->getString('field.size.KB'),
                $this->Loader->L10N->getString('field.size.MB'),
                $this->Loader->L10N->getString('field.size.GB'),
                $this->Loader->L10N->getString('field.size.TB'),
                $this->Loader->L10N->getString('field.size.PB'),
                'document.getElementById',
                'document.all'
            );
        }
        if ($DirValue['type'] === 'timezone') {
            $DirValue['choices'] = ['SYSTEM' => $this->Loader->L10N->getString('field.Use system default timezone')];
            foreach (array_unique(\DateTimeZone::listIdentifiers()) as $DirValue['ChoiceValue']) {
                $DirValue['choices'][$DirValue['ChoiceValue']] = $DirValue['ChoiceValue'];
            }
        }
        if (isset($DirValue['choices'])) {
            if ($DirValue['type'] === 'checkbox' || (isset($DirValue['style']) && $DirValue['style'] === 'radio')) {
                if ($DirValue['type'] === 'checkbox' && isset($DirValue['labels']) && is_array($DirValue['labels'])) {
                    $DirValue['gridV'] = 'gridVB';
                    $ThisDir['FieldOut'] = sprintf(
                        '<div style="display:grid;margin:auto 38px;grid-template-columns:repeat(%s) auto;text-align:%s">',
                        count($DirValue['labels']) . ',minmax(0, 1fr)',
                        $FE['FE_Align']
                    );
                    $DirValue['HasLabels'] = true;
                    foreach ($DirValue['labels'] as $DirValue['ThisLabel']) {
                        $DirValue['gridV'] = ($DirValue['gridV']) === 'gridVB' ? 'gridVA' : 'gridVB';
                        $this->replaceLabelWithL10N($DirValue['ThisLabel']);
                        $ThisDir['FieldOut'] .= sprintf(
                            '<div class="gridboxitem configMatrixLabel %s">%s</div>',
                            $DirValue['gridV'],
                            $DirValue['ThisLabel']
                        );
                    }
                    $ThisDir['FieldOut'] .= '<div class="gridboxitem"></div>';
                } else {
                    $ThisDir['FieldOut'] = sprintf(
                        '<div style="display:grid;margin:auto 38px;grid-template-columns:19px auto;text-align:%s">',
                        $FE['FE_Align']
                    );
                    $DirValue['HasLabels'] = false;
                }
            } else {
                $ThisDir['FieldOut'] = sprintf(
                    '<select class="auto" style="text-transform:capitalize" name="%1$s" id="%1$s_field"%2$s>',
                    $ThisDir['DirLangKey'],
                    $ThisDir['Trigger']
                );
            }
            $DirValue['gridH'] = 'gridHB';
            foreach ($DirValue['choices'] as $ChoiceKey => $ChoiceValue) {
                if (isset($DirValue['choice_filter'])) {
                    if (
                        !is_string($ChoiceValue) ||
                        (method_exists($this, $DirValue['choice_filter']) && !$this->{$DirValue['choice_filter']}($ChoiceKey, $ChoiceValue))
                    ) {
                        continue;
                    }
                }
                $DirValue['gridV'] = 'gridVB';
                $DirValue['gridH'] = ($DirValue['gridH']) === 'gridHB' ? 'gridHA' : 'gridHB';
                $ChoiceValue = $this->Loader->timeFormat($this->Loader->Time, $ChoiceValue);
                if (strpos($ChoiceValue, '{') !== false) {
                    $ChoiceValue = $this->Loader->parse([], $ChoiceValue, true);
                }
                $this->replaceLabelWithL10N($ChoiceValue);
                if ($DirValue['type'] === 'checkbox') {
                    if ($DirValue['HasLabels']) {
                        foreach ($DirValue['labels'] as $DirValue['ThisLabelKey'] => $DirValue['ThisLabel']) {
                            $DirValue['gridV'] = ($DirValue['gridV']) === 'gridVB' ? 'gridVA' : 'gridVB';
                            $ThisDir['FieldOut'] .= sprintf(
                                '<div class="gridboxcheckcell %4$s %5$s"><label class="gridlabel"><input%3$s type="checkbox" class="auto" name="%1$s" id="%1$s"%2$s /></label></div>',
                                $ThisDir['DirLangKey'] . '_' . $ChoiceKey . '_' . $DirValue['ThisLabelKey'],
                                $this->Loader->Request->inCsv(
                                    $ChoiceKey . ':' . $DirValue['ThisLabelKey'],
                                    $this->Loader->Configuration[$CatKey][$DirKey]
                                ) ? ' checked' : '',
                                $ThisDir['Trigger'],
                                $DirValue['gridV'],
                                $DirValue['gridH']
                            );
                            $ThisDir['Reset'] .= sprintf(
                                'document.getElementById(\'%s\').checked=%s;',
                                $ThisDir['DirLangKey'] . '_' . $ChoiceKey . '_' . $DirValue['ThisLabelKey'],
                                isset($this->Loader->ConfigurationDefaults[$CatKey][$DirKey]['default']) && $this->Loader->Request->inCsv(
                                    $ChoiceKey . ':' . $DirValue['ThisLabelKey'],
                                    $this->Loader->ConfigurationDefaults[$CatKey][$DirKey]['default']
                                ) ? 'true' : 'false'
                            );
                        }
                        $ThisDir['FieldOut'] .= sprintf(
                            '<div class="gridboxitem %s %s">%s</div>',
                            $DirValue['gridH'],
                            (count($DirValue['labels']) % 2) === 0 ? 'vrte' : 'vrto',
                            $ChoiceValue
                        );
                    } else {
                        $ThisDir['FieldOut'] .= sprintf(
                            '<div class="gridboxcheckcell gridVA %5$s"><label class="gridlabel"><input%4$s type="checkbox" class="auto" name="%1$s" id="%1$s"%2$s /></label></div><div class="gridboxitem %5$s"><label for="%1$s" class="s">%3$s</label></div>',
                            $ThisDir['DirLangKey'] . '_' . $ChoiceKey,
                            $this->Loader->Request->inCsv(
                                $ChoiceKey,
                                $this->Loader->Configuration[$CatKey][$DirKey]
                            ) ? ' checked' : '',
                            $ChoiceValue,
                            $ThisDir['Trigger'],
                            $DirValue['gridH']
                        );
                        $ThisDir['Reset'] .= sprintf(
                            'document.getElementById(\'%s\').checked=%s;',
                            $ThisDir['DirLangKey'] . '_' . $ChoiceKey,
                            isset($this->Loader->ConfigurationDefaults[$CatKey][$DirKey]['default']) && $this->Loader->Request->inCsv(
                                $ChoiceKey,
                                $this->Loader->ConfigurationDefaults[$CatKey][$DirKey]['default']
                            ) ? 'true' : 'false'
                        );
                    }
                } elseif (isset($DirValue['style']) && $DirValue['style'] === 'radio') {
                    if (strpos($ChoiceValue, "\n")) {
                        $ChoiceValue = explode("\n", $ChoiceValue);
                        $ThisDir['FieldOut'] .= sprintf(
                            '<div class="gridboxstretch gridVA %5$s"><label class="gridlabel"><input%4$s type="radio" class="auto" name="%6$s" id="%1$s" value="%7$s"%2$s /></label></div><div class="gridboxstretch %5$s"><label for="%1$s"><span class="s">%3$s</span><br />%8$s</label></div>',
                            $ThisDir['DirLangKey'] . '_' . $ChoiceKey,
                            $ChoiceKey === $this->Loader->Configuration[$CatKey][$DirKey] ? ' checked' : '',
                            $ChoiceValue[0],
                            $ThisDir['Trigger'],
                            $DirValue['gridH'],
                            $ThisDir['DirLangKey'],
                            $ChoiceKey,
                            $ChoiceValue[1]
                        );
                    } else {
                        $ThisDir['FieldOut'] .= sprintf(
                            '<div class="gridboxcheckcell gridVA %5$s"><label class="gridlabel"><input%4$s type="radio" class="auto" name="%6$s" id="%1$s" value="%7$s"%2$s /></label></div><div class="gridboxitem %5$s"><label for="%1$s" class="s">%3$s</label></div>',
                            $ThisDir['DirLangKey'] . '_' . $ChoiceKey,
                            $ChoiceKey === $this->Loader->Configuration[$CatKey][$DirKey] ? ' checked' : '',
                            $ChoiceValue,
                            $ThisDir['Trigger'],
                            $DirValue['gridH'],
                            $ThisDir['DirLangKey'],
                            $ChoiceKey
                        );
                    }
                    if (
                        isset($this->Loader->ConfigurationDefaults[$CatKey][$DirKey]['default']) &&
                        $ChoiceKey === $this->Loader->ConfigurationDefaults[$CatKey][$DirKey]['default']
                    ) {
                        $ThisDir['Reset'] .= sprintf(
                            'document.getElementById(\'%s\').checked=true;',
                            $ThisDir['DirLangKey'] . '_' . $ChoiceKey
                        );
                    }
                } else {
                    $ThisDir['FieldOut'] .= sprintf(
                        '<option style="text-transform:capitalize" value="%s"%s>%s</option>',
                        $ChoiceKey,
                        $ChoiceKey === $this->Loader->Configuration[$CatKey][$DirKey] ? ' selected' : '',
                        $ChoiceValue
                    );
                    if (
                        isset($this->Loader->ConfigurationDefaults[$CatKey][$DirKey]['default']) &&
                        $ChoiceKey === $this->Loader->ConfigurationDefaults[$CatKey][$DirKey]['default']
                    ) {
                        $ThisDir['Reset'] .= sprintf(
                            'document.getElementById(\'%s_field\').value=\'%s\';',
                            $ThisDir['DirLangKey'],
                            addcslashes($ChoiceKey, "\n'\"\\")
                        );
                    }
                }
            }
            if ($DirValue['type'] === 'checkbox' || (isset($DirValue['style']) && $DirValue['style'] === 'radio')) {
                $ThisDir['FieldOut'] .= '</div>';
            } else {
                $ThisDir['SelectOther'] = !isset($DirValue['choices'][$this->Loader->Configuration[$CatKey][$DirKey]]);
                $ThisDir['FieldOut'] .= empty($DirValue['allow_other']) ? '</select>' : sprintf(
                    '<option value="Other"%1$s>%2$s</option></select><input type="text"%3$s class="auto" name="%4$s" id="%4$s_field" value="%5$s" />',
                    $ThisDir['SelectOther'] ? ' selected' : '',
                    $this->Loader->L10N->getString('label.Other'),
                    $ThisDir['SelectOther'] ? '' : ' style="display:none"',
                    $ThisDir['DirLangKeyOther'],
                    $this->Loader->Configuration[$CatKey][$DirKey]
                );
            }
        } elseif ($DirValue['type'] === 'bool') {
            $ThisDir['FieldOut'] = sprintf(
                '<select class="auto" name="%1$s" id="%1$s_field"%2$s><option value="true"%5$s>%3$s</option><option value="false"%6$s>%4$s</option></select>',
                $ThisDir['DirLangKey'],
                $ThisDir['Trigger'],
                $this->Loader->L10N->getString('field.True (True)'),
                $this->Loader->L10N->getString('field.False (False)'),
                ($this->Loader->Configuration[$CatKey][$DirKey] ? ' selected' : ''),
                ($this->Loader->Configuration[$CatKey][$DirKey] ? '' : ' selected')
            );
            $ThisDir['Reset'] .= sprintf(
                'document.getElementById(\'%s_field\').value=\'%s\';',
                $ThisDir['DirLangKey'],
                empty($this->Loader->ConfigurationDefaults[$CatKey][$DirKey]['default']) ? 'false' : 'true'
            );
        } elseif ($DirValue['type'] === 'float' || $DirValue['type'] === 'int') {
            $ThisDir['FieldAppend'] = '';
            if (isset($DirValue['step'])) {
                $ThisDir['FieldAppend'] .= ' step="' . $DirValue['step'] . '"';
            }
            $ThisDir['FieldAppend'] .= $ThisDir['Trigger'];
            if ($DirValue['type'] === 'int') {
                $ThisDir['FieldAppend'] .= ' inputmode="numeric"';
                if (isset($DirValue['pattern'])) {
                    $ThisDir['FieldAppend'] .= ' pattern="' . $DirValue['pattern'] . '"';
                } else {
                    $ThisDir['FieldAppend'] .= (!isset($DirValue['min']) || $DirValue['min'] < 0) ? ' pattern="^-?\d*$"' : ' pattern="^\d*$"';
                }
            } elseif (isset($DirValue['pattern'])) {
                $ThisDir['FieldAppend'] .= ' pattern="' . $DirValue['pattern'] . '"';
            }
            foreach (['min', 'max'] as $ThisDir['ParamTry']) {
                if (isset($DirValue[$ThisDir['ParamTry']])) {
                    $ThisDir['FieldAppend'] .= ' ' . $ThisDir['ParamTry'] . '="' . $DirValue[$ThisDir['ParamTry']] . '"';
                }
            }
            $ThisDir['FieldOut'] = sprintf(
                '<input type="number" name="%1$s" id="%1$s_field" value="%2$s"%3$s />',
                $ThisDir['DirLangKey'],
                $this->Loader->Configuration[$CatKey][$DirKey],
                $ThisDir['FieldAppend']
            );
            if (isset($this->Loader->ConfigurationDefaults[$CatKey][$DirKey]['default'])) {
                $ThisDir['Reset'] .= sprintf(
                    'document.getElementById(\'%s_field\').value=%s;',
                    $ThisDir['DirLangKey'],
                    $this->Loader->ConfigurationDefaults[$CatKey][$DirKey]['default']
                );
            }
        } elseif ($DirValue['type'] === 'url' || (
            empty($DirValue['autocomplete']) && $DirValue['type'] === 'string'
        )) {
            $ThisDir['FieldOut'] = sprintf(
                '<textarea name="%1$s" id="%1$s_field" class="half"%2$s%3$s>%4$s</textarea>',
                $ThisDir['DirLangKey'],
                $ThisDir['autocomplete'],
                $ThisDir['Trigger'],
                $this->Loader->Configuration[$CatKey][$DirKey]
            );
            if (isset($this->Loader->ConfigurationDefaults[$CatKey][$DirKey]['default'])) {
                $ThisDir['Reset'] .= sprintf(
                    'document.getElementById(\'%s_field\').value=\'%s\';',
                    $ThisDir['DirLangKey'],
                    addcslashes($this->Loader->ConfigurationDefaults[$CatKey][$DirKey]['default'], "\n'\"\\")
                );
            }
        } else {
            $ThisDir['FieldAppend'] = $ThisDir['autocomplete'] . $ThisDir['Trigger'];
            if (isset($DirValue['pattern'])) {
                $ThisDir['FieldAppend'] .= ' pattern="' . $DirValue['pattern'] . '"';
            } elseif ($DirValue['type'] === 'kb') {
                $ThisDir['FieldAppend'] .= ' pattern="^\d+(\.\d+)?\s*(?:[KkMmGgTtPpOoBb]|К|к|М|м|Г|г|Т|т|П|п|Ｋ|ｋ|Ｍ|ｍ|Ｇ|ｇ|Ｔ|ｔ|Ｐ|ｐ|Б|б|Ｂ|ｂ)(?:[OoBb]|Б|б|Ｂ|ｂ)?$"';
            }
            $ThisDir['FieldOut'] = sprintf(
                '<input type="text" name="%1$s" id="%1$s_field" value="%2$s"%3$s />',
                $ThisDir['DirLangKey'],
                $this->Loader->Configuration[$CatKey][$DirKey],
                $ThisDir['FieldAppend']
            );
            if (isset($this->Loader->ConfigurationDefaults[$CatKey][$DirKey]['default'])) {
                $ThisDir['Reset'] .= sprintf(
                    'document.getElementById(\'%s_field\').value=\'%s\';',
                    $ThisDir['DirLangKey'],
                    addcslashes($this->Loader->ConfigurationDefaults[$CatKey][$DirKey]['default'], "\n'\"\\")
                );
            }
        }
        $ThisDir['FieldOut'] .= $ThisDir['Preview'];

        /** Check extension and class requirements. */
        if (!empty($DirValue['required'])) {
            $ThisDir['FieldOut'] .= '<small>';
            foreach ($DirValue['required'] as $DirValue['Requirement'] => $DirValue['Friendly']) {
                if (isset($ReqsLookupCache[$DirValue['Requirement']])) {
                    $ThisDir['FieldOut'] .= $ReqsLookupCache[$DirValue['Requirement']];
                    continue;
                }
                if (substr($DirValue['Requirement'], 0, 1) === '\\') {
                    $ReqsLookupCache[$DirValue['Requirement']] = '<br /><span class="txtGn">✔️ ' . sprintf(
                        $this->Loader->L10N->getString('label.%s is available'),
                        $DirValue['Friendly']
                    ) . '</span>';
                } elseif (extension_loaded($DirValue['Requirement'])) {
                    $DirValue['ReqVersion'] = (new \ReflectionExtension($DirValue['Requirement']))->getVersion();
                    $ReqsLookupCache[$DirValue['Requirement']] = '<br /><span class="txtGn">✔️ ' . sprintf(
                        $this->Loader->L10N->getString('label.%s is available (%s)'),
                        $DirValue['Friendly'],
                        $DirValue['ReqVersion']
                    ) . '</span>';
                } else {
                    $ReqsLookupCache[$DirValue['Requirement']] = '<br /><span class="txtRd">❌ ' . sprintf(
                        $this->Loader->L10N->getString('label.%s is not available'),
                        $DirValue['Friendly']
                    ) . '</span>';
                }
                $ThisDir['FieldOut'] .= $ReqsLookupCache[$DirValue['Requirement']];
            }
            $ThisDir['FieldOut'] .= '</small>';
        }

        /** Provide hints, useful for users to better understand the directive at hand. */
        if (!empty($DirValue['hints'])) {
            $ThisDir['Hints'] = $this->Loader->L10N->arrayFromL10nToArray($DirValue['hints']);
            foreach ($ThisDir['Hints'] as $ThisDir['HintKey'] => $ThisDir['HintValue']) {
                if (is_int($ThisDir['HintKey'])) {
                    $ThisDir['FieldOut'] .= sprintf("\n<br /><br />%s", $ThisDir['HintValue']);
                    continue;
                }
                $ThisDir['FieldOut'] .= sprintf(
                    "\n<br /><br /><span class=\"s\">%s</span> %s",
                    $ThisDir['HintKey'],
                    $ThisDir['HintValue']
                );
            }
        }

        /** Provide additional information, useful for users to better understand the directive at hand. */
        if (!empty($DirValue['See also']) && is_array($DirValue['See also'])) {
            $ThisDir['FieldOut'] .= sprintf("\n<br /><br />%s<ul>\n", $this->Loader->L10N->getString('label.See also'));
            foreach ($DirValue['See also'] as $DirValue['Ref key'] => $DirValue['Ref link']) {
                $ThisDir['FieldOut'] .= sprintf(
                    '<li><a dir="ltr" href="%s">%s</a></li>',
                    $DirValue['Ref link'],
                    $this->Loader->L10N->getString($DirValue['Ref key']) ?: $DirValue['Ref key']
                );
            }
            $ThisDir['FieldOut'] .= "\n</ul>";
        }

        /** Reset to defaults. */
        if ($ThisDir['Reset'] !== '') {
            if (isset($DirValue['preview'], $DirValue['default']) && $DirValue['preview'] === 'allow_other') {
                $ThisDir['Reset'] .= sprintf(
                    'hideid(\'%1$s_field\');getElementById(\'%1$s_field\').value=\'%2$s\';',
                    $ThisDir['DirLangKeyOther'],
                    $DirValue['default']
                );
            }
            $ThisDir['FieldOut'] .= sprintf(
                '<br /><br /><input type="button" class="reset" onclick="javascript:%s" value="↺ %s" />',
                $ThisDir['Reset'],
                $this->Loader->L10N->getString('field.Reset')
            );
        }

        /** Finalise configuration row. */
        $FE['ConfigFields'] .= $this->Loader->parse($ThisDir, $ConfigurationRow, true);

        /** Rebuilding in order to strip out orphaned data. */
        if (isset($NewConfig)) {
            if (!isset($NewConfig[$CatKey])) {
                $NewConfig[$CatKey] = [];
            }
            $NewConfig[$CatKey][$DirKey] = $this->Loader->Configuration[$CatKey][$DirKey];
        }
    }
    $CatKeyFriendly = $this->Loader->L10N->getString('config.' . $CatKey . '_label') ?: $CatKey;
    $FE['Indexes'] .= sprintf(
        '<li><span class="comCat">%s</span><ul class="comSub">%s</ul></li>',
        $CatKeyFriendly,
        $CatData
    );
    $FE['ConfigFields'] .= "</table></span>\n";
}

/** Cleanup. */
unset($ReqsLookupCache);

/** Update the currently active configuration file if any changes were made. */
if ($ConfigurationModified || isset($NewConfig)) {
    if (isset($NewConfig)) {
        foreach ($this->Loader->Configuration as $CatKey => $CatValue) {
            if (substr($CatKey, 0, 5) !== 'user.') {
                continue;
            }
            $NewConfig[$CatKey] = $CatValue;
        }
        $this->Loader->Configuration = $NewConfig;
        unset($NewConfig);
    }
    if ($this->Loader->updateConfiguration()) {
        $FE['state_msg'] = $this->Loader->L10N->getString('response.Configuration successfully updated');
    } else {
        $FE['state_msg'] = $this->Loader->L10N->getString('response.Failed to update configuration');
    }
}

$FE['Indexes'] .= '</ul>';

/** Parse output. */
$FE['FE_Content'] = $this->Loader->parse($FE, $this->Loader->readFile($this->getAssetPath('_config.html')), true) . $MenuToggle;

/** Send output. */
echo $this->sendOutput($FE);

return;
