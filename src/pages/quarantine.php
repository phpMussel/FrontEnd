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
 * This file: The quarantine page (last modified: 2023.12.12).
 */

if (!isset($Page) || $Page !== 'quarantine' || $this->Permissions !== 1) {
    die;
}

/** Page initial prepwork. */
$this->initialPrepwork($FE, $this->Loader->L10N->getString('link.Quarantine'), $this->Loader->L10N->getString('tip.Quarantine'));

/** Display how to enable quarantine if currently disabled. */
if (!$this->Loader->Configuration['quarantine']['quarantine_key']) {
    $FE['state_msg'] .= '<span class="txtRd">' . $this->Loader->L10N->getString('tip.Quarantine is currently disabled') . '</span><br />';
}

/** Generate confirm button. */
$FE['Confirm-DeleteAll'] = $this->generateConfirm($this->Loader->L10N->getString('field.Delete all'), 'quarantineForm');

/** Append necessary quarantine JS. */
$FE['JS'] .= "function qOpt(e){b=document.getElementById(e+'-S'),'delete-file'==b.value?hideid(e):showid(e)}\n";

/** A form was submitted. */
if (
    !empty($_POST['qfu']) &&
    !empty($_POST['do']) &&
    !is_dir($this->Loader->QuarantinePath . $_POST['qfu']) &&
    is_readable($this->Loader->QuarantinePath . $_POST['qfu'])
) {
    if ($_POST['do'] === 'delete-file') {
        $FE['state_msg'] .= '<code>' . $_POST['qfu'] . '</code> ' . $this->Loader->L10N->getString(
            unlink($this->Loader->QuarantinePath . $_POST['qfu']) ? 'response.File successfully deleted' : 'response.Failed to delete'
        ) . '<br />';
    } elseif ($_POST['do'] === 'download-file' || $_POST['do'] === 'restore-file') {
        if (empty($_POST['qkey'])) {
            $FE['state_msg'] .= '<code>' . $_POST['qfu'] . '</code> ' . $this->Loader->L10N->getString('response.Incorrect quarantine key') . '<br />';
        } else {
            /** Attempt to restore the file. */
            $Restored = $this->quarantineRestore($this->Loader->QuarantinePath . $_POST['qfu'], $_POST['qkey']);

            /** Restore success! */
            if (empty($this->InstanceCache['RestoreStatus'])) {
                /** Download the file. */
                if ($_POST['do'] === 'download-file') {
                    header('Content-Type: application/octet-stream');
                    header('Content-Transfer-Encoding: Binary');
                    header('Content-disposition: attachment; filename="' . basename($_POST['qfu']) . '.restored"');
                    echo $Restored;
                    return;
                }

                /** Restore the file. */
                $Handle = fopen($this->Loader->QuarantinePath . $_POST['qfu'] . '.restored', 'wb');
                fwrite($Handle, $Restored);
                fclose($Handle);
                $FE['state_msg'] .= '<code>' . $_POST['qfu'] . '.restored</code> ' . $this->Loader->L10N->getString('response.File successfully restored') . '<br />';
            } elseif ($this->InstanceCache['RestoreStatus'] === 2) {
                /** Corrupted file! */
                $FE['state_msg'] .= '<code>' . $_POST['qfu'] . '</code> ' . $this->Loader->L10N->getString('response.Corrupted file') . '<br />';
            } else {
                /** Incorrect quarantine key! */
                $FE['state_msg'] .= '<code>' . $_POST['qfu'] . '</code> ' . $this->Loader->L10N->getString('response.Incorrect quarantine key') . '<br />';
            }

            /** Cleanup. */
            unset($this->InstanceCache['RestoreStatus'], $Restored);
        }
    }
}

/** Template for quarantine files row. */
$QuarantineRow = $this->Loader->readFile($this->getAssetPath('_quarantine_row.html'));

/** Fetch quarantine data array. */
$FilesInQuarantine = $this->quarantineRecursiveList();

/** Number of files in quarantine. */
$FilesInQuarantineCount = count($FilesInQuarantine);

/** Number of files in quarantine state message. */
$FE['state_msg'] .= sprintf(
    $this->Loader->L10N->getPlural($FilesInQuarantineCount, 'state_quarantine'),
    '<span class="txtRd">' . $this->NumberFormatter->format($FilesInQuarantineCount) . '</span>'
) . '<br />';

/** Initialise quarantine data string. */
$FE['FilesInQuarantine'] = '';

/** Process quarantine files data. */
foreach ($FilesInQuarantine as $ThisFile) {
    $FE['FilesInQuarantine'] .= $this->Loader->parse($FE, $this->Loader->parse($ThisFile, $QuarantineRow), true);
}

/** Cleanup. */
unset($ThisFile, $FilesInQuarantineCount, $FilesInQuarantine);

/** Parse output. */
$FE['FE_Content'] = $this->Loader->parse($FE, $this->Loader->readFile($this->getAssetPath('_quarantine.html')), true);

/** Send output. */
echo $this->sendOutput($FE);

return;
