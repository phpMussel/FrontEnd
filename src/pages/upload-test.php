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
 * This file: The upload testing page (last modified: 2026.09.05).
 */

namespace phpMussel\FrontEnd;

if (!isset($Page) || $Page !== 'upload-test' || empty($this->PermissionsMap['Complete access'])) {
    die;
}

/** Page initial prepwork. */
$this->initialPrepwork($FE, $this->Loader->L10N->getString('link.Upload Testing'), $this->Loader->L10N->getString('tip.Upload Testing'));

/** Append upload test JS. */
$FE['JS'] .=
    "var x=1;more=function(){var t='field'+x,e=document.createElement('div');" .
    "e.setAttribute('class','spanner'),e.setAttribute('id',t),e.setAttribute(" .
    "'style','opacity:0;animation:UplT 2s ease 0s 1 normal'),(z=document.crea" .
    "teElement('input')).setAttribute('name','upload_test[]'),z.setAttribute(" .
    "'type','file'),e.appendChild(z),document.getElementById('upload_fields')" .
    ".appendChild(e),setTimeout(function(){document.getElementById(t).style.o" .
    "pacity='1'},1999),x++};";

$FE['MaxFilesize'] = $this->Loader->readBytes($this->Loader->Configuration['files']['filesize_limit']);

/** Parse output. */
$FE['FE_Content'] = $this->Loader->parse($FE, $this->Loader->readFile($this->getAssetPath('_upload_test.html')), true);

/** Send output. */
echo $this->sendOutput($FE);

return;
