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
 * This file: The accounts page (last modified: 2026.09.03).
 */

namespace phpMussel\FrontEnd;

if (!isset($Page) || $Page !== 'accounts' || $this->Permissions !== 1) {
    die;
}

/** A form has been submitted. */
if ($FE['FormTarget'] === 'accounts' && !empty($_POST['do'])) {
    /** Create a new account. */
    if ($_POST['do'] === 'create-account' && !empty($_POST['username']) && !empty($_POST['password']) && !empty($_POST['permissions'])) {
        $TryPath = 'user.' . $_POST['username'];
        $TryPass = \password_hash($_POST['password'], $this->DefaultAlgo);
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
        $TryPass = \password_hash($_POST['password'], $this->DefaultAlgo);
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

    /** Append JavaScript specific to the accounts page. */
    $FE['JS'] .= $this->Loader->parse([
        'Loading' => $this->Loader->L10N->getString('label.Loading_'),
        'PasswordStrengthLow' => $this->Loader->L10N->getString('label.Password strength') . $this->Loader->L10N->getString('label.risk.Low'),
        'PasswordStrengthMedium' => $this->Loader->L10N->getString('label.Password strength') . $this->Loader->L10N->getString('label.risk.Medium'),
        'PasswordStrengthHigh' => $this->Loader->L10N->getString('label.Password strength') . $this->Loader->L10N->getString('label.risk.High')
    ], $this->Loader->readFile($this->getAssetPath('accounts.js')));

    $AccountsRow = $this->Loader->readFile($this->getAssetPath('_accounts_row.html'));
    $FE['Accounts'] = '';
    $FE['PassInOnListWarn'] = '<br \>' . \str_replace('\'', '\\\'', $this->Loader->L10N->getString('warning.Extremely common passwords should be avoided'));

    $LI = ['Possible' => []];
    foreach ($this->Loader->Cache->getAllEntries() as $LI['KeyName'] => $LI['KeyData']) {
        if (isset($LI['KeyData']['Time']) && $LI['KeyData']['Time'] > 0 && $LI['KeyData']['Time'] < $this->Loader->Time) {
            continue;
        }
        if (\strlen($LI['KeyName']) > 64) {
            $LI['Try'] = \substr($LI['KeyName'], 0, -64);
            if (isset($this->Loader->Configuration['user.' . $LI['Try']])) {
                $LI['Possible'][$LI['Try']] = true;
            }
        }
    }
    $LI = $LI['Possible'];

    foreach ($this->Loader->Configuration as $CatKey => $CatValues) {
        if (\substr($CatKey, 0, 5) !== 'user.' || !\is_array($CatValues)) {
            continue;
        }
        $RowInfo = [
            'AccUsername' => \substr($CatKey, 5),
            'AccPassword' => $CatValues['password'] ?? '',
            'AccPermissions' => (int)($CatValues['permissions'] ?? ''),
            'AccWarnings' => ''
        ];
        $RowInfo['AccPasswordLen'] = \strlen($RowInfo['AccPassword']);
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
        } elseif (
            ($RowInfo['AccPasswordLen'] !== 60 && $RowInfo['AccPasswordLen'] !== 96 && $RowInfo['AccPasswordLen'] !== 97) ||
            ($RowInfo['AccPasswordLen'] === 60 && !\preg_match('/^\$2.\$\d\d\$/', $RowInfo['AccPassword'])) ||
            ($RowInfo['AccPasswordLen'] === 96 && !\preg_match('/^\$argon2i\$/', $RowInfo['AccPassword'])) ||
            ($RowInfo['AccPasswordLen'] === 97 && !\preg_match('/^\$argon2id\$/', $RowInfo['AccPassword']))
        ) {
            $RowInfo['AccWarnings'] .= '<br /><div class="txtRd">' . $this->Loader->L10N->getString('warning.This account is not using a valid password') . '</div>';
        }

        /** Logged in notice. */
        if (isset($LI[$RowInfo['AccUsername']])) {
            $RowInfo['AccWarnings'] .= '<br /><div class="txtGn">' . $this->Loader->L10N->getString('label.Logged in') . '</div>';
        }

        $RowInfo['AccID'] = \bin2hex($RowInfo['AccUsername']);
        $RowInfo['AccUsername'] = \htmlentities($RowInfo['AccUsername']);
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
