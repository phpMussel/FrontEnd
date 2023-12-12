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
 * This file: The accounts page (last modified: 2023.12.12).
 */

if (!isset($Page) || $Page !== 'accounts' || $this->Permissions !== 1) {
    die;
}

/** $_POST overrides for mobile display. */
if (!empty($_POST['username']) && !empty($_POST['do_mob']) && (!empty($_POST['password_mob']) || $_POST['do_mob'] === 'delete-account')) {
    $_POST['do'] = $_POST['do_mob'];
}
if (empty($_POST['username']) && !empty($_POST['username_mob'])) {
    $_POST['username'] = $_POST['username_mob'];
}
if (empty($_POST['permissions']) && !empty($_POST['permissions_mob'])) {
    $_POST['permissions'] = $_POST['permissions_mob'];
}
if (empty($_POST['password']) && !empty($_POST['password_mob'])) {
    $_POST['password'] = $_POST['password_mob'];
}

/** A form has been submitted. */
if ($FE['FormTarget'] === 'accounts' && !empty($_POST['do'])) {
    /** Create a new account. */
    if ($_POST['do'] === 'create-account' && !empty($_POST['username']) && !empty($_POST['password']) && !empty($_POST['permissions'])) {
        $TryPath = 'user.' . $_POST['username'];
        $TryPass = password_hash($_POST['password'], $this->DefaultAlgo);
        $TryPermissions = (int)$_POST['permissions'];
        if (isset($this->Loader->Configuration[$TryPath])) {
            $FE['state_msg'] = $this->Loader->L10N->getString('response.An account with that username already exists');
        } else {
            $this->Loader->Configuration[$TryPath] = ['password' => $TryPass, 'permissions' => $TryPermissions];
            if ($this->Loader->updateConfiguration()) {
                $FE['state_msg'] = $this->Loader->L10N->getString('response.Account successfully created');
            } else {
                $FE['state_msg'] = $this->Loader->L10N->getString('response.Failed to create');
            }
        }
    }

    /** Delete an account. */
    if ($_POST['do'] === 'delete-account' && !empty($_POST['username'])) {
        $TryPath = 'user.' . $_POST['username'];
        if (!isset($this->Loader->Configuration[$TryPath])) {
            $FE['state_msg'] = $this->Loader->L10N->getString('response.That account doesn_t exist');
        } else {
            unset($this->Loader->Configuration[$TryPath]);
            if ($this->Loader->updateConfiguration()) {
                $FE['state_msg'] = $this->Loader->L10N->getString('response.Account successfully deleted');
            } else {
                $FE['state_msg'] = $this->Loader->L10N->getString('response.Failed to delete');
            }
        }
    }

    /** Update an account password. */
    if ($_POST['do'] === 'update-password' && !empty($_POST['username']) && !empty($_POST['password'])) {
        $TryPath = 'user.' . $_POST['username'];
        $TryPass = password_hash($_POST['password'], $this->DefaultAlgo);
        if (!isset($this->Loader->Configuration[$TryPath])) {
            $FE['state_msg'] = $this->Loader->L10N->getString('response.That account doesn_t exist');
        } else {
            $this->Loader->Configuration[$TryPath]['password'] = $TryPass;
            if ($this->Loader->updateConfiguration()) {
                $FE['state_msg'] = $this->Loader->L10N->getString('response.Password successfully updated');
            } else {
                $FE['state_msg'] = $this->Loader->L10N->getString('response.Failed to update');
            }
        }
    }
}

if (!$FE['ASYNC']) {
    /** Page initial prepwork. */
    $this->initialPrepwork($FE, $this->Loader->L10N->getString('link.Accounts'), $this->Loader->L10N->getString('tip.Accounts'));

    /** Append async globals. */
    $FE['JS'] .= sprintf(
        'window[%3$s]=\'accounts\';function acc(e,d,i,t){var o=function(e){%4$se)' .
        '},a=function(){%4$s\'%1$s\')};window.username=%2$s(e).value,window.passw' .
        'ord=%2$s(d).value,window.do=%2$s(t).value,\'delete-account\'==window.do&' .
        '&$(\'POST\',\'\',[%3$s,\'username\',\'password\',\'do\'],a,function(e){%' .
        '4$se),hideid(i)},o),\'update-password\'==window.do&&$(\'POST\',\'\',[%3$' .
        's,\'username\',\'password\',\'do\'],a,o,o)}' . "\n",
        $this->Loader->L10N->getString('label.Loading_'),
        'document.getElementById',
        "'phpmussel-form-target'",
        "w('stateMsg',"
    );

    $AccountsRow = $this->Loader->readFile($this->getAssetPath('_accounts_row.html'));
    $FE['Accounts'] = '';

    $LI = ['Possible' => []];
    foreach ($this->Loader->Cache->getAllEntries() as $LI['KeyName'] => $LI['KeyData']) {
        if (isset($LI['KeyData']['Time']) && $LI['KeyData']['Time'] > 0 && $LI['KeyData']['Time'] < $this->Loader->Time) {
            continue;
        }
        if (strlen($LI['KeyName']) > 64) {
            $LI['Try'] = substr($LI['KeyName'], 0, -64);
            if (isset($this->Loader->Configuration['user.' . $LI['Try']])) {
                $LI['Possible'][$LI['Try']] = true;
            }
        }
    }
    $LI = $LI['Possible'];

    foreach ($this->Loader->Configuration as $CatKey => $CatValues) {
        if (substr($CatKey, 0, 5) !== 'user.' || !is_array($CatValues)) {
            continue;
        }
        $RowInfo = [
            'AccUsername' => substr($CatKey, 5),
            'AccPassword' => $CatValues['password'] ?? '',
            'AccPermissions' => (int)($CatValues['permissions'] ?? ''),
            'AccWarnings' => ''
        ];
        if ($RowInfo['AccPermissions'] === 1) {
            $RowInfo['AccPermissions'] = $this->Loader->L10N->getString('label.Complete access');
        } elseif ($RowInfo['AccPermissions'] === 2) {
            $RowInfo['AccPermissions'] = $this->Loader->L10N->getString('label.Logs access only');
        } else {
            $RowInfo['AccPermissions'] = $this->Loader->L10N->getString('response.Error');
        }

        /** Account password warnings. */
        if ($RowInfo['AccPassword'] === $this->DefaultPassword) {
            $RowInfo['AccWarnings'] .= '<br /><div class="txtRd">' . $this->Loader->L10N->getString('warning.Using the default password') . '</div>';
        } elseif ((
            strlen($RowInfo['AccPassword']) !== 60 &&
            strlen($RowInfo['AccPassword']) !== 96 &&
            strlen($RowInfo['AccPassword']) !== 97
        ) || (
            strlen($RowInfo['AccPassword']) === 60 &&
            !preg_match('/^\$2.\$\d\d\$/', $RowInfo['AccPassword'])
        ) || (
            strlen($RowInfo['AccPassword']) === 96 &&
            !preg_match('/^\$argon2i\$/', $RowInfo['AccPassword'])
        ) || (
            strlen($RowInfo['AccPassword']) === 97 &&
            !preg_match('/^\$argon2id\$/', $RowInfo['AccPassword'])
        )) {
            $RowInfo['AccWarnings'] .= '<br /><div class="txtRd">' . $this->Loader->L10N->getString('warning.This account is not using a valid password') . '</div>';
        }

        /** Logged in notice. */
        if (isset($LI[$RowInfo['AccUsername']])) {
            $RowInfo['AccWarnings'] .= '<br /><div class="txtGn">' . $this->Loader->L10N->getString('label.Logged in') . '</div>';
        }

        $RowInfo['AccID'] = bin2hex($RowInfo['AccUsername']);
        $RowInfo['AccUsername'] = htmlentities($RowInfo['AccUsername']);
        $FE['Accounts'] .= $this->Loader->parse($RowInfo, $AccountsRow, true);
    }
    unset($RowInfo, $LI);
}

if ($FE['ASYNC']) {
    /** Send output (async). */
    echo $FE['state_msg'];
} else {
    /** Parse output. */
    $FE['FE_Content'] = $this->Loader->parse($FE, $this->Loader->readFile($this->getAssetPath('_accounts.html')), true);

    /** Send output. */
    echo $this->sendOutput($FE);
}

return;
