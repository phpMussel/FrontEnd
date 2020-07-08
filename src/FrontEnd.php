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
 * This file: Front-end handler (last modified: 2020.07.08).
 */

namespace phpMussel\FrontEnd;

class FrontEnd
{
    /**
     * @var \phpMussel\Core\Loader The instantiated loader object.
     */
    private $Loader;

    /**
     * @var \phpMussel\Core\Scanner The instantiated scanner object.
     */
    private $Scanner;

    /**
     * @var \Maikuolan\Common\NumberFormatter Used to format numbers according
     *      to the specified configuration.
     */
    private $NumberFormatter;

    /**
     * @var string The path to the front-end asset files.
     */
    private $AssetsPath = __DIR__ . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . 'assets' . DIRECTORY_SEPARATOR;

    /**
     * @var string The path to the front-end L10N files.
     */
    private $L10NPath = __DIR__ . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . 'l10n' . DIRECTORY_SEPARATOR;

    /**
     * @var int Minimum length for generateSalt.
     */
    private $SaltMinLen = 32;

    /**
     * @var int Maximum length for generateSalt.
     */
    private $SaltMaxLen = 72;

    /**
     * @var int Minimum characters to use for generateSalt.
     */
    private $SaltMinChar = 1;

    /**
     * @var int Maximum characters to use for generateSalt.
     */
    private $SaltMaxChar = 255;

    /**
     * @var int Minimum integer to use for twoFactorNumber.
     */
    private $TwoFactorMinInt = 10000000;

    /**
     * @var int Maximum integer to use for twoFactorNumber.
     */
    private $TwoFactorMaxInt = 99999999;

    /**
     * @var int How many seconds until a session expires.
     */
    private $SessionTTL = 604800;

    /**
     * @var int How many seconds until a two-factor authentication codes expire.
     */
    private $TwoFactorTTL = 600;

    /**
     * @var array The query parts (needed for determining which view to select).
     */
    public $QueryVariables = [];

    /**
     * @var string|int The default hash algorithm to use (int for PHP < 7.4;
     *      string for PHP >= 7.4).
     */
    private $DefaultAlgo;

    /**
     * @var string Derived from HTTP_HOST (used for writing cookies).
     */
    private $Host = '';

    /**
     * @var int User permissions.
     *      -1 = Attempted to log in; Login failed (i.e., bad credentials).
     *       0 = Not logged in.
     *       1 = Logged in; Complete access.
     *       2 = Logged in; Logs access only.
     *       3 = Logged in; Awaiting two-factor authentication.
     */
    private $Permissions = 0;

    /**
     * @var string Will be populated by the current session data.
     */
    private $ThisSession = '';

    /**
     * @var string The default password hash ("password").
     */
    private $DefaultPassword = '$2y$10$FPF5Im9MELEvF5AYuuRMSO.QKoYVpsiu1YU9aDClgrU57XtLof/dK';

    /**
     * @var string The currently logged in user.
     */
    private $User = '';

    /**
     * Construct the loader.
     *
     * @param \phpMussel\Core\Loader $Loader The instantiated loader object, passed by reference.
     */
    public function __construct(\phpMussel\Core\Loader &$Loader, \phpMussel\Core\Scanner &$Scanner)
    {
        /** Link the loader to this instance. */
        $this->Loader = &$Loader;

        /** Link the scanner to this instance. */
        $this->Scanner = &$Scanner;
        $this->Scanner->CalledFrom = 'FrontEnd';

        /** Load phpMussel front-end handler configuration defaults and perform fallbacks. */
        if (
            is_readable($this->AssetsPath . 'config.yml') &&
            $Configuration = $this->Loader->readFile($this->AssetsPath . 'config.yml')
        ) {
            $Defaults = [];
            $this->Loader->YAML->process($Configuration, $Defaults);
            if (isset($Defaults)) {
                $this->Loader->fallback($Defaults);
                $this->Loader->ConfigurationDefaults = array_merge_recursive($this->Loader->ConfigurationDefaults, $Defaults);
            }
        }

        /** Register log paths. */
        $this->Loader->InstanceCache['LogPaths'][] = $this->Loader->Configuration['frontend']['frontend_log'];

        /** Load phpMussel front-end handler L10N data. */
        $this->Loader->loadL10N($this->L10NPath);

        /** Instantiate the NumberFormatter object. */
        $this->NumberFormatter = new \Maikuolan\Common\NumberFormatter($this->Loader->Configuration['frontend']['numbers']);

        /** Set default hashing algorithm. */
        $this->DefaultAlgo = (
            !empty($this->Loader->Configuration['frontend']['default_algo']) &&
            defined($this->Loader->Configuration['frontend']['default_algo'])
        ) ? constant($this->Loader->Configuration['frontend']['default_algo']) : PASSWORD_DEFAULT;

        /** Process the request query parts (if it exists). */
        if (!empty($_SERVER['QUERY_STRING'])) {
            parse_str($_SERVER['QUERY_STRING'], $QueryVariables);
        } else {
            $QueryVariables = [];
        }

        /** Set it to the instance. */
        if (is_array($QueryVariables) && !empty($QueryVariables)) {
            $this->QueryVariables = $QueryVariables;
        }

        /** Fallback for which view to select. */
        if (empty($this->QueryVariables['phpmussel-page'])) {
            $this->QueryVariables['phpmussel-page'] = '';
        }

        /** Fetch domain segment of HTTP_HOST (needed for writing cookies safely). */
        $this->Host = empty($_SERVER['HTTP_HOST']) ? '' : (
            strpos($_SERVER['HTTP_HOST'], ':') === false ? $_SERVER['HTTP_HOST'] : substr($_SERVER['HTTP_HOST'], 0, strpos($_SERVER['HTTP_HOST'], ':'))
        );
    }

    /**
     * View a page.
     *
     * @param string $Page Which page to use (defers to that defined by the
     *      query when not supplied by the call).
     */
    public function view(string $Page = '')
    {
        /** Brute-force protection. */
        if ((
            ($LoginAttempts = (int)$this->Loader->Cache->getEntry('LoginAttempts' . $_SERVER[$this->Loader->Configuration['core']['ipaddr']])) &&
            ($LoginAttempts >= $this->Loader->Configuration['frontend']['max_login_attempts'])
        ) || (
            ($Failed2FA = (int)$this->Loader->Cache->getEntry('Failed2FA' . $_SERVER[$this->Loader->Configuration['core']['ipaddr']])) &&
            ($Failed2FA >= $this->Loader->Configuration['frontend']['max_login_attempts'])
        )) {
            header('Content-Type: text/plain');
            echo '[phpMussel] ' . $this->Loader->L10N->getString('max_login_attempts_exceeded');
            return;
        }

        /** Apply fallback. */
        if ($Page === '') {
            $Page = $this->QueryVariables['phpmussel-page'];
        }

        /** Populate common page variables. */
        $FE = [
            /** Main front-end HTML template file. */
            'Template' => $this->Loader->readFileBlocks($this->getAssetPath('frontend.html')),

            /** Populated by front-end JavaScript data as per needed. */
            'JS' => '',

            /** Current default language. */
            'FE_Lang' => $this->Loader->Configuration['core']['lang'],

            /** Font magnification. */
            'magnification' => $this->Loader->Configuration['frontend']['magnification'],

            /** Define active configuration file. */
            'ActiveConfigFile' => realpath($this->Loader->ConfigurationPath),

            /** Current time and date. */
            'DateTime' => $this->Loader->timeFormat($this->Loader->Time, $this->Loader->Configuration['core']['time_format']),

            /** How the script identifies itself. */
            'ScriptIdent' => $this->Loader->ScriptIdent,

            /** Current theme. */
            'theme' => $this->Loader->Configuration['frontend']['theme'],

            /**
             * Sourced from either $_POST['username'] or $_COOKIE['PHPMUSSEL-ADMIN'] (the
             * username claimed by the client).
             */
            'User' => '',

            /** Will be populated by messages reflecting the current request state. */
            'state_msg' => '',

            /**
             * Populated by [Home | Log Out] by default;
             * Replaced by [Log Out] for some specific pages (e.g., the homepage).
             */
            'bNav' => sprintf(
                '<a href="?">%s</a> | <a href="?phpmussel-page=logout">%s</a>',
                $this->Loader->L10N->getString('link_home'),
                $this->Loader->L10N->getString('link_log_out')
            ),

            /** The user agent of the current request. */
            'UA' => empty($_SERVER['HTTP_USER_AGENT']) ? '' : $_SERVER['HTTP_USER_AGENT'],

            /** The IP address of the current request. */
            'YourIP' => empty($_SERVER[$this->Loader->Configuration['core']['ipaddr']]) ? '' : $_SERVER[$this->Loader->Configuration['core']['ipaddr']],

            /** Asynchronous mode. */
            'ASYNC' => !empty($_POST['ASYNC']),

            /** Will be populated by the page title. */
            'FE_Title' => '',

            /**
             * Defining some links here instead of in the template files or the L10N
             * data so that it'll be easier to change them in the future if and when
             * needed due to less potential duplication across the codebase (this
             * excludes links shown at the front-end homepage).
             */
            'URL-Chat' => 'https://gitter.im/phpMussel2/Lobby',
            'URL-Documentation' => 'https://phpmussel.github.io/#documentation',
            'URL-Website' => 'https://phpmussel.github.io/',

            /** To be populated by warnings. */
            'Warnings' => [],

            /** Set the current request's form target. */
            'FormTarget' => $_POST['phpmussel-form-target'] ?? ''
        ];

        /** Append "@ Gitter" to the chat link text. */
        if (isset($this->Loader->L10N->Data['link_chat'])) {
            $this->Loader->L10N->Data['link_chat'] .= '@Gitter';
        } else {
            $this->Loader->L10N->Data['link_chat'] = '@Gitter';
        }

        /** Assign website link text. */
        $this->Loader->L10N->Data['link_website'] = 'phpMussel@GitHub';

        /** Warns if maintenance mode is enabled. */
        if ($this->Loader->Configuration['core']['maintenance_mode']) {
            $FE['Warnings'][] = '<span class="txtRd"><u>' . $this->Loader->L10N->getString('state_maintenance_mode') . '</u></span>';
        }

        /** Warns if no signature files are active. */
        if (empty($this->Loader->Configuration['signatures']['active'])) {
            $FE['Warnings'][] = '<span class="txtRd"><u>' . $this->Loader->L10N->getString('warning_signatures_1') . '</u></span>';
        }

        /** Prepare warnings. */
        $FE['Warnings'] = count($FE['Warnings']) ? "\n<div class=\"center\">⚠️ " . implode(" ⚠️<br />\n⚠️ ", $FE['Warnings']) . ' ⚠️</div><hr />' : '';

        /** Menu toggle JavaScript, needed by some front-end pages. */
        $MenuToggle =
            '<script type="text/javascript">var i, toggler = document.getElementsByClassName("comCat");' .
            'for (i = 0; i < toggler.length; i++) toggler[i].addEventListener("click", function() {' .
            'this.parentElement.querySelector(".comSub").classList.toggle("active"), !this.classList.toggle("caret-down") && this.classList.toggle("caret-up") && setTimeout(function(t) {' .
            't.classList.toggle("caret-up")}, 200, this)});</script>';

        /** Fetch pips data. */
        $PipsPath = $this->getAssetPath('pips.yml');
        $PipsData = $this->Loader->readFileBlocks($PipsPath);
        $Pips = [];
        if ($PipsData) {
            $this->Loader->YAML->process($PipsData, $Pips);
            $FE['PIP_Key'] = $Pips['Key'];
            $FE['PIP_Key_64'] = base64_encode($Pips['Key']);
            $FE['PIP_Key2'] = $Pips['Key2'];
            $FE['PIP_Key2_64'] = base64_encode($Pips['Key2']);
        }

        /** A fix for correctly displaying LTR/RTL text. */
        if (empty($this->Loader->L10N->Data['Text Direction']) || $this->Loader->L10N->Data['Text Direction'] !== 'rtl') {
            $this->Loader->L10N->Data['Text Direction'] = 'ltr';
            $FE['FE_Align'] = 'left';
            $FE['FE_Align_Reverse'] = 'right';
            $FE['PIP_Input'] = $Pips['Right'];
            $FE['PIP_Input_64'] = base64_encode($Pips['Right']);
            $FE['Gradient_Degree'] = 90;
            $FE['Half_Border'] = 'solid solid none none';
            $FE['45deg'] = '45deg';
        } else {
            $FE['FE_Align'] = 'right';
            $FE['FE_Align_Reverse'] = 'left';
            $FE['PIP_Input'] = $Pips['Left'];
            $FE['PIP_Input_64'] = base64_encode($Pips['Left']);
            $FE['Gradient_Degree'] = 270;
            $FE['Half_Border'] = 'solid none none solid';
            $FE['45deg'] = '-45deg';
        }

        /** Cleanup. */
        unset($Pips, $PipsData, $PipsPath);

        /** Fire event: "frontend_before". */
        $this->Loader->Events->fireEvent('frontend_before_page', '', $FE);

        /** A simple passthru for non-private theme images and related data. */
        if (!empty($this->QueryVariables['phpmussel-asset'])) {
            /** Guard. */
            if (!$ThisAsset = $this->getAssetPath($this->QueryVariables['phpmussel-asset'], true)) {
                return;
            }

            if (is_readable($ThisAsset) && ($Delimiter = strrpos($ThisAsset, '.')) !== false) {
                $AssetType = strtolower(substr($ThisAsset, $Delimiter + 1));
                if ($AssetType === 'jpeg') {
                    $AssetType = 'jpg';
                }
                $Success = false;
                if (preg_match('~^(?:gif|jpg|png|webp)$~', $AssetType)) {
                    /** Set asset mime-type (images). */
                    header('Content-Type: image/' . $AssetType);
                    $Success = true;
                } elseif ($AssetType === 'js') {
                    /** Set asset mime-type (JavaScript). */
                    header('Content-Type: text/javascript');
                    $Success = true;
                }
                if ($Success) {
                    if (!empty($this->QueryVariables['theme'])) {
                        /** Prevents needlessly reloading static assets. */
                        header('Last-Modified: ' . gmdate(DATE_RFC1123, filemtime($ThisAsset)));
                    }
                    /** Send asset data. */
                    echo $this->Loader->readFileBlocks($ThisAsset);
                }
            }
            return;
        }

        /** A simple passthru for the front-end CSS. */
        if ($Page === 'css') {
            header('Content-Type: text/css');
            echo $this->Loader->parse($FE, $this->Loader->parse(
                $this->Loader->L10N->Data,
                $this->Loader->readFileBlocks($this->getAssetPath('frontend.css'))
            ));
            return;
        }

        /** A simple passthru for the favicon. */
        if ($Page === 'favicon') {
            header('Content-Type: image/png');
            echo $this->Loader->getFavicon();
            return;
        }

        /** Attempt to log the user in. */
        if ($FE['FormTarget'] === 'login') {
            $this->Permissions = -1;
            if (!empty($_POST['username']) && empty($_POST['password'])) {
                $FE['state_msg'] = $this->Loader->L10N->getString('response_login_password_field_empty');
            } elseif (empty($_POST['username']) && !empty($_POST['password'])) {
                $FE['state_msg'] = $this->Loader->L10N->getString('response_login_username_field_empty');
            } elseif (!empty($_POST['username']) && !empty($_POST['password'])) {
                $ConfigUserPath = 'user.' . $_POST['username'];
                if (isset(
                        $this->Loader->Configuration[$ConfigUserPath],
                        $this->Loader->Configuration[$ConfigUserPath]['password'],
                        $this->Loader->Configuration[$ConfigUserPath]['permissions']
                ) &&
                    !empty($this->Loader->Configuration[$ConfigUserPath]['password']) &&
                    !empty($this->Loader->Configuration[$ConfigUserPath]['permissions'])
                ) {
                    if (password_verify($_POST['password'], $this->Loader->Configuration[$ConfigUserPath]['password'])) {
                        $this->Loader->Cache->deleteEntry('LoginAttempts' . $_SERVER[$this->Loader->Configuration['core']['ipaddr']]);
                        $Permissions = (int)$this->Loader->Configuration[$ConfigUserPath]['permissions'];
                        if ($Permissions !== 1 && $Permissions !== 2) {
                            $FE['state_msg'] = $this->Loader->L10N->getString('response_login_wrong_endpoint');
                        } else {
                            $TryUser = $_POST['username'];
                            $SessionKey = hash('sha256', $this->generateSalt());
                            $Cookie = $_POST['username'] . $SessionKey;
                            setcookie('PHPMUSSEL-ADMIN', $Cookie, $this->Loader->Time + $this->SessionTTL, '/', $this->Host, false, true);
                            $this->ThisSession = $TryUser . ',' . password_hash($SessionKey, $this->DefaultAlgo);

                            /** Prepare 2FA email. */
                            if (
                                !empty($this->Loader->InstanceCache['enable_two_factor']) &&
                                preg_match('~^.+@.+$~', $TryUser) &&
                                ($TwoFactorMessage = $this->Loader->L10N->getString('msg_template_2fa')) &&
                                ($TwoFactorSubject = $this->Loader->L10N->getString('msg_subject_2fa'))
                            ) {
                                $TwoFactorState = ['Number' => $this->twoFactorNumber()];
                                $TwoFactorState['Hash'] = password_hash($TwoFactorState['Number'], $this->DefaultAlgo);
                                $this->Loader->Cache->setEntry('TwoFactorState:' . $Cookie, '0' . $TwoFactorState['Hash'], $this->Loader->Time + $this->TwoFactorTTL);
                                $TwoFactorState['Template'] = sprintf($TwoFactorMessage, $TryUser, $TwoFactorState['Number']);
                                if (preg_match('~^[^<>]+<[^<>]+>$~', $TryUser)) {
                                    $TwoFactorState['Name'] = trim(preg_replace('~^([^<>]+)<[^<>]+>$~', '\1', $TryUser));
                                    $TwoFactorState['Address'] = trim(preg_replace('~^[^<>]+<([^<>]+)>$~', '\1', $TryUser));
                                } else {
                                    $TwoFactorState['Name'] = trim($TryUser);
                                    $TwoFactorState['Address'] = $TwoFactorState['Name'];
                                }
                                $EventData = [
                                    [['Name' => $TwoFactorState['Name'], 'Address' => $TwoFactorState['Address']]],
                                    $TwoFactorSubject,
                                    $TwoFactorState['Template'],
                                    strip_tags($TwoFactorState['Template']),
                                    ''
                                ];
                                $this->Loader->Events->fireEvent('sendMail', '', ...$EventData);
                                $this->Permissions = 3;
                            } else {
                                $this->Loader->Cache->setEntry($Cookie, $this->ThisSession, $this->Loader->Time + $this->SessionTTL);
                                $this->Permissions = 1;
                            }
                        }
                    } else {
                        $FE['state_msg'] = $this->Loader->L10N->getString('response_login_invalid_password');
                    }
                } else {
                    $FE['state_msg'] = $this->Loader->L10N->getString('response_login_invalid_username');
                }
            }

            if ($this->Permissions < 0) {
                if ($FE['state_msg']) {
                    $LoginAttempts++;
                    $TimeToAdd = ($LoginAttempts > 4) ? ($LoginAttempts - 4) * 86400 : 86400;
                    $this->Loader->Cache->setEntry('LoginAttempts' . $_SERVER[$this->Loader->Configuration['core']['ipaddr']], $LoginAttempts, $this->Loader->Time + $TimeToAdd);
                    $LoggerMessage = $FE['state_msg'];
                }
            } elseif ($this->Permissions === 3) {
                $LoggerMessage = $this->Loader->L10N->getString('state_logged_in_2fa_pending');
            } else {
                $this->User = $TryUser;
                $LoggerMessage = $this->Loader->L10N->getString('state_logged_in');
            }

            /** Handle front-end logging. */
            $this->frontendLogger($_SERVER[$this->Loader->Configuration['core']['ipaddr']], $TryUser ?? $this->User, $LoggerMessage ?? '');
        }

        /** Determine whether the user has logged in. */
        elseif (!empty($_COOKIE['PHPMUSSEL-ADMIN'])) {
            $this->Permissions = -1;
            if (
                ($TrySession = $this->Loader->Cache->getEntry($_COOKIE['PHPMUSSEL-ADMIN'])) &&
                ($SessionDel = strpos($TrySession, ',')) !== false
            ) {
                $SessionHash = substr($TrySession, $SessionDel + 1);
                $SessionUser = substr($TrySession, 0, $SessionDel);
            }
            if (!empty($SessionHash) && !empty($SessionUser)) {
                $SessionUserLen = strlen($SessionUser);
                $SessionKey = substr($_COOKIE['PHPMUSSEL-ADMIN'], $SessionUserLen);
                $CookieUser = substr($_COOKIE['PHPMUSSEL-ADMIN'], 0, $SessionUserLen);
                $ConfigUserPath = 'user.' . $CookieUser;
                if ($CookieUser === $SessionUser && password_verify($SessionKey, $SessionHash) && isset(
                    $this->Loader->Configuration[$ConfigUserPath],
                    $this->Loader->Configuration[$ConfigUserPath]['permissions']
                )) {
                    $this->Permissions = (int)$this->Loader->Configuration[$ConfigUserPath]['permissions'];
                    $this->User = $SessionUser;

                    /** Handle 2FA stuff here. */
                    if (!empty($this->Loader->InstanceCache['enable_two_factor']) && preg_match('~^.+@.+$~', $SessionUser)) {
                        $TwoFactorState = $this->Loader->Cache->getEntry('TwoFactorState:' . $_COOKIE['PHPMUSSEL-ADMIN']);
                        $Try = (int)substr($TwoFactorState, 0, 1);
                        if ($Try === 0 && $FE['FormTarget'] === '2fa' && !empty($_POST['2fa'])) {

                            /** User has submitted a 2FA code. Attempt to verify it. */
                            if (password_verify($_POST['2fa'], substr($TwoFactorState, 1))) {
                                $this->Loader->Cache->setEntry('TwoFactorState:' . $_COOKIE['PHPMUSSEL-ADMIN'], '1', $this->Loader->Time + $this->SessionTTL);
                                $Try = 1;
                                $this->Loader->Cache->deleteEntry('Failed2FA' . $_SERVER[$this->Loader->Configuration['core']['ipaddr']]);
                                if ($this->Loader->Configuration['frontend']['frontend_log']) {
                                    $this->frontendLogger($_SERVER[$this->Loader->Configuration['core']['ipaddr']], $SessionUser, $this->Loader->L10N->getString('response_2fa_valid'));
                                }
                            } else {
                                $Failed2FA++;
                                $TimeToAdd = ($Failed2FA > 4) ? ($Failed2FA - 4) * 86400 : 86400;
                                $this->Loader->Cache->setEntry('Failed2FA' . $_SERVER[$this->Loader->Configuration['core']['ipaddr']], $Failed2FA, $this->Loader->Time + $TimeToAdd);
                                if ($this->Loader->Configuration['frontend']['frontend_log']) {
                                    $this->frontendLogger($_SERVER[$this->Loader->Configuration['core']['ipaddr']], $SessionUser, $this->Loader->L10N->getString('response_2fa_invalid'));
                                }
                                $FE['state_msg'] = $this->Loader->L10N->getString('response_2fa_invalid');
                            }

                            /** Revert permissions if not authenticated. */
                            if ($Try !== 1) {
                                $this->Permissions = 3;
                            }
                        }
                    }
                }
            }
        }

        /** The user is attempting an asynchronous request without adequate permissions. */
        if ($FE['ASYNC'] && $this->Permissions !== 1) {
            header('HTTP/1.0 403 Forbidden');
            header('HTTP/1.1 403 Forbidden');
            header('Status: 403 Forbidden');
            echo $this->Loader->L10N->getString('state_async_deny');
            return;
        }

        /** Executed only for users that are logged in or awaiting two-factor authentication. */
        if ($this->Permissions > 0) {

            /** Log the user out. */
            if ($Page === 'logout') {
                $this->Loader->Cache->deleteEntry($this->ThisSession);
                $this->Loader->Cache->deleteEntry('TwoFactorState:' . $_COOKIE['PHPMUSSEL-ADMIN']);
                $this->ThisSession = '';
                $this->User = '';
                $this->Permissions = 0;
                setcookie('PHPMUSSEL-ADMIN', '', -1, '/', $this->Host, false, true);
                $this->frontendLogger($_SERVER[$this->Loader->Configuration['core']['ipaddr']], $SessionUser, $this->Loader->L10N->getString('state_logged_out'));
            }

            if ($this->Permissions === 1) {
                /** If the user has complete access. */
                $FE['nav'] = $this->Loader->parse(
                    $this->Loader->L10N->Data,
                    $this->Loader->parse($FE, $this->Loader->readFileBlocks($this->getAssetPath('_nav_complete_access.html')))
                );
            } elseif ($this->Permissions === 2) {
                /** If the user has logs access only. */
                $FE['nav'] = $this->Loader->parse(
                    $this->Loader->L10N->Data,
                    $this->Loader->parse($FE, $this->Loader->readFileBlocks($this->getAssetPath('_nav_logs_access_only.html')))
                );
            } else {
                /** No valid navigation state. */
                $FE['nav'] = '';
            }
        }

        /** The user hasn't logged in, or hasn't authenticated yet. */
        if ($this->Permissions < 1 || $this->Permissions === 3) {
            /** Page initial prepwork. */
            $this->initialPrepwork($FE, $this->Loader->L10N->getString('title_login'), $this->Loader->L10N->getString('tip_login'), false);

            if ($this->Permissions === 3) {
                /** Provide the option to log out (omit home link). */
                $FE['bNav'] = sprintf('<a href="?phpmussel-page=logout">%s</a><br />', $this->Loader->L10N->getString('link_log_out'));

                /** Show them the two-factor authentication page. */
                $FE['FE_Content'] = $this->Loader->parse(
                    $this->Loader->L10N->Data,
                    $this->Loader->parse($FE, $this->Loader->readFileBlocks($this->getAssetPath('_2fa.html')))
                );
            } else {
                /** Omit the log out and home links. */
                $FE['bNav'] = '';

                /** Format error message. */
                if (!empty($FE['state_msg'])) {
                    $FE['state_msg'] = '<div class="txtRd">' . $FE['state_msg'] . '<br /><br /></div>';
                }

                /** Show them the login page. */
                $FE['FE_Content'] = $this->Loader->parse(
                    $this->Loader->L10N->Data,
                    $this->Loader->parse($FE, $this->Loader->readFileBlocks($this->getAssetPath('_login.html')))
                );
            }
            /** Send output. */
            echo $this->sendOutput($FE);
            return;
        }

        /**
         * The user has logged in, but hasn't selected anything to view. Show them the
         * front-end home page.
         */
        if ($Page === '') {
            /** Page initial prepwork. */
            $this->initialPrepwork($FE, $this->Loader->L10N->getString('link_home'), $this->Loader->L10N->getString('tip_home'), false);

            /** phpMussel version used. */
            $FE['ScriptVersion'] = $this->Loader->ScriptVersion;

            /** PHP version used. */
            $FE['info_php'] = PHP_VERSION;

            /** SAPI used. */
            $FE['info_sapi'] = php_sapi_name();

            /** Operating system used. */
            $FE['info_os'] = php_uname();

            /** Provide the log out and home links. */
            $FE['bNav'] = sprintf('<a href="?phpmussel-page=logout">%s</a>', $this->Loader->L10N->getString('link_log_out'));

            /** Build repository backup locations information. */
            $FE['BackupLocations'] = implode(' | ', [
                '<a href="https://bitbucket.org/Maikuolan/phpmussel" hreflang="en-US" target="_blank" rel="noopener external">phpMussel@Bitbucket</a>',
                '<a href="https://sourceforge.net/projects/phpmussel/" hreflang="en-US" target="_blank" rel="noopener external">phpMussel@SourceForge</a>'
            ]);

            /** Where to find remote version information? */
            $RemoteVerPath = 'https://raw.githubusercontent.com/Maikuolan/Compatibility-Charts/gh-pages/';

            /** Fetch remote phpMussel version information and cache it if necessary. */
            if (!($RemoteYAMLphpMussel = $this->Loader->Cache->getEntry('phpmussel-ver.yaml'))) {
                $RemoteYAMLphpMussel = $this->Loader->request($RemoteVerPath . 'phpmussel-ver.yaml', [], 8);
                $this->Loader->Cache->setEntry('phpmussel-ver.yaml', $RemoteYAMLphpMussel ?: '-', $this->Loader->Time + 86400);
            }

            /** Process remote phpMussel version information. */
            if (empty($RemoteYAMLphpMussel)) {
                /** phpMussel latest stable. */
                $FE['info_phpmussel_stable'] = $this->Loader->L10N->getString('response_error');

                /** phpMussel latest unstable. */
                $FE['info_phpmussel_unstable'] = $this->Loader->L10N->getString('response_error');

                /** phpMussel branch latest stable. */
                $FE['info_phpmussel_branch'] = $this->Loader->L10N->getString('response_error');
            } else {
                $RemoteYAMLphpMusselArray = (new \Maikuolan\Common\YAML($RemoteYAMLphpMussel))->Data;

                /** phpMussel latest stable. */
                $FE['info_phpmussel_stable'] = empty($RemoteYAMLphpMusselArray['Stable']) ?
                    $this->Loader->L10N->getString('response_error') : $RemoteYAMLphpMusselArray['Stable'];

                /** phpMussel latest unstable. */
                $FE['info_phpmussel_unstable'] = empty($RemoteYAMLphpMusselArray['Unstable']) ?
                    $this->Loader->L10N->getString('response_error') : $RemoteYAMLphpMusselArray['Unstable'];

                /** phpMussel branch latest stable. */
                if ($ThisBranch = substr($FE['ScriptVersion'], 0, strpos($FE['ScriptVersion'], '.') ?: 0)) {
                    $ThisBranch = 'v' . ($ThisBranch ?: 1);
                    $FE['info_phpmussel_branch'] = empty($RemoteYAMLphpMusselArray['Branch'][$ThisBranch]['Latest']) ?
                        $this->Loader->L10N->getString('response_error') : $RemoteYAMLphpMusselArray['Branch'][$ThisBranch]['Latest'];
                } else {
                    $FE['info_php_branch'] = $this->Loader->L10N->getString('response_error');
                }
            }

            /** Cleanup. */
            unset($RemoteYAMLphpMusselArray, $RemoteYAMLphpMussel);

            /** Fetch remote PHP version information and cache it if necessary. */
            if (!($RemoteYamlPHP = $this->Loader->Cache->getEntry('php-ver.yaml'))) {
                $RemoteYamlPHP = $this->Loader->request($RemoteVerPath . 'php-ver.yaml', [], 8);
                $this->Loader->Cache->setEntry('php-ver.yaml', $RemoteYamlPHP ?: '-', $this->Loader->Time + 86400);
            }

            /** Process remote PHP version information. */
            if (empty($RemoteYamlPHP)) {
                /** PHP latest stable. */
                $FE['info_php_stable'] = $this->Loader->L10N->getString('response_error');

                /** PHP latest unstable. */
                $FE['info_php_unstable'] = $this->Loader->L10N->getString('response_error');

                /** PHP branch latest stable. */
                $FE['info_php_branch'] = $this->Loader->L10N->getString('response_error');
            } else {
                $RemoteYamlPhpArray = (new \Maikuolan\Common\YAML($RemoteYamlPHP))->Data;

                /** PHP latest stable. */
                $FE['info_php_stable'] = empty($RemoteYamlPhpArray['Stable']) ?
                    $this->Loader->L10N->getString('response_error') : $RemoteYamlPhpArray['Stable'];

                /** PHP latest unstable. */
                $FE['info_php_unstable'] = empty($RemoteYamlPhpArray['Unstable']) ?
                    $this->Loader->L10N->getString('response_error') : $RemoteYamlPhpArray['Unstable'];

                /** PHP branch latest stable. */
                if ($ThisBranch = substr(PHP_VERSION, 0, strpos(PHP_VERSION, '.') ?: 0)) {
                    $ThisBranch .= substr(PHP_VERSION, strlen($ThisBranch) + 1, strpos(PHP_VERSION, '.', strlen($ThisBranch)) ?: 0);
                    $ThisBranch = 'php' . $ThisBranch;
                    $FE['info_php_branch'] = empty($RemoteYamlPhpArray['Branch'][$ThisBranch]['Latest']) ?
                        $this->Loader->L10N->getString('response_error') : $RemoteYamlPhpArray['Branch'][$ThisBranch]['Latest'];
                } else {
                    $FE['info_php_branch'] = $this->Loader->L10N->getString('response_error');
                }
            }

            /** Cleanup. */
            unset($RemoteYamlPhpArray, $RemoteYamlPHP, $ThisBranch, $RemoteVerPath);

            /** Extension availability. */
            $FE['Extensions'] = [];
            foreach ([
                ['Lib' => 'pcre', 'Name' => 'PCRE'],
                ['Lib' => 'curl', 'Name' => 'cURL'],
                ['Lib' => 'apcu', 'Name' => 'APCu'],
                ['Lib' => 'memcached', 'Name' => 'Memcached'],
                ['Lib' => 'redis', 'Name' => 'Redis'],
                ['Lib' => 'pdo', 'Name' => 'PDO', 'Drivers' => (class_exists('\PDO') ? \PDO::getAvailableDrivers() : [])],
                ['Lib' => 'bz2', 'Name' => 'Bz2'],
                ['Lib' => 'lzf', 'Name' => 'Lzf'],
                ['Lib' => 'rar', 'Name' => 'Rar'],
                ['Lib' => 'zip', 'Name' => 'Zip']
            ] as $ThisExtension) {
                if (extension_loaded($ThisExtension['Lib'])) {
                    $ExtensionVersion = (new \ReflectionExtension($ThisExtension['Lib']))->getVersion();
                    $ThisResponse = '<span class="txtGn">' . $this->Loader->L10N->getString('response_yes') . ' (' . $ExtensionVersion . ')';
                    if (!empty($ThisExtension['Drivers'])) {
                        $ThisResponse .= ', {' . implode(', ', $ThisExtension['Drivers']) . '}';
                    }
                    $ThisResponse .= '</span>';
                } else {
                    $ThisResponse = '<span class="txtRd">' . $this->Loader->L10N->getString('response_no') . '</span>';
                }
                $FE['Extensions'][] = '    <li><small>' . $this->ltrInRtf(sprintf(
                    '%1$s➡%2$s',
                    $ThisExtension['Name'],
                    $ThisResponse
                )) . '</small></li>';
            }
            $FE['Extensions'] = implode("\n", $FE['Extensions']);
            $FE['ExtensionIsAvailable'] = $this->ltrInRtf($this->Loader->L10N->getString('label_extension') . '➡' . $this->Loader->L10N->getString('label_installed_available'));
            unset($ExtensionVersion, $ThisResponse, $ThisExtension);

            /** Parse output. */
            $FE['FE_Content'] = $this->Loader->parse(
                $this->Loader->L10N->Data,
                $this->Loader->parse($FE, $this->Loader->readFileBlocks($this->getAssetPath('_home.html')))
            ) . $MenuToggle;

            /** Send output. */
            echo $this->sendOutput($FE);
            return;
        }

        /** Accounts. */
        if ($Page === 'accounts' && $this->Permissions === 1) {
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
                    $TryUser = $_POST['username'];
                    $TryPath = 'user.' . $_POST['username'];
                    $TryPass = password_hash($_POST['password'], $this->DefaultAlgo);
                    $TryPermissions = (int)$_POST['permissions'];
                    if (isset($this->Loader->Configuration[$TryPath])) {
                        $FE['state_msg'] = $this->Loader->L10N->getString('response_accounts_already_exists');
                    } else {
                        $this->Loader->Configuration[$TryPath] = ['password' => $TryPass, 'permissions' => $TryPermissions];
                        if ($this->Loader->updateConfiguration()) {
                            $FE['state_msg'] = $this->Loader->L10N->getString('response_accounts_created');
                        } else {
                            $FE['state_msg'] = $this->Loader->L10N->getString('response_failed_to_create');
                        }
                    }
                }

                /** Delete an account. */
                if ($_POST['do'] === 'delete-account' && !empty($_POST['username'])) {
                    $TryUser = $_POST['username'];
                    $TryPath = 'user.' . $_POST['username'];
                    if (!isset($this->Loader->Configuration[$TryPath])) {
                        $FE['state_msg'] = $this->Loader->L10N->getString('response_accounts_doesnt_exist');
                    } else {
                        unset($this->Loader->Configuration[$TryPath]);
                        if ($this->Loader->updateConfiguration()) {
                            $FE['state_msg'] = $this->Loader->L10N->getString('response_accounts_deleted');
                        } else {
                            $FE['state_msg'] = $this->Loader->L10N->getString('response_failed_to_delete');
                        }
                    }
                }

                /** Update an account password. */
                if ($_POST['do'] === 'update-password' && !empty($_POST['username']) && !empty($_POST['password'])) {
                    $TryUser = $_POST['username'];
                    $TryPath = 'user.' . $_POST['username'];
                    $TryPass = password_hash($_POST['password'], $this->DefaultAlgo);
                    if (!isset($this->Loader->Configuration[$TryPath])) {
                        $FE['state_msg'] = $this->Loader->L10N->getString('response_accounts_doesnt_exist');
                    } else {
                        $this->Loader->Configuration[$TryPath]['password'] = $TryPass;
                        if ($this->Loader->updateConfiguration()) {
                            $FE['state_msg'] = $this->Loader->L10N->getString('response_accounts_password_updated');
                        } else {
                            $FE['state_msg'] = $this->Loader->L10N->getString('response_failed_to_update');
                        }
                    }
                }
            }

            if (!$FE['ASYNC']) {
                /** Page initial prepwork. */
                $this->initialPrepwork($FE, $this->Loader->L10N->getString('link_accounts'), $this->Loader->L10N->getString('tip_accounts'));

                /** Append async globals. */
                $FE['JS'] .= sprintf(
                    'window[%3$s]=\'accounts\';function acc(e,d,i,t){var o=function(e){%4$se)' .
                    '},a=function(){%4$s\'%1$s\')};window.username=%2$s(e).value,window.passw' .
                    'ord=%2$s(d).value,window.do=%2$s(t).value,\'delete-account\'==window.do&' .
                    '&$(\'POST\',\'\',[%3$s,\'username\',\'password\',\'do\'],a,function(e){%' .
                    '4$se),hideid(i)},o),\'update-password\'==window.do&&$(\'POST\',\'\',[%3$' .
                    's,\'username\',\'password\',\'do\'],a,o,o)}' . "\n",
                    $this->Loader->L10N->getString('state_loading'),
                    'document.getElementById',
                    "'phpmussel-form-target'",
                    "w('stateMsg',"
                );

                $AccountsRow = $this->Loader->readFileBlocks($this->getAssetPath('_accounts_row.html'));
                $FE['Accounts'] = '';
                $NewLineOffSet = 0;

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
                        $RowInfo['AccPermissions'] = $this->Loader->L10N->getString('state_complete_access');
                    } elseif ($RowInfo['AccPermissions'] === 2) {
                        $RowInfo['AccPermissions'] = $this->Loader->L10N->getString('state_logs_access_only');
                    } else {
                        $RowInfo['AccPermissions'] = $this->Loader->L10N->getString('response_error');
                    }

                    /** Account password warnings. */
                    if ($RowInfo['AccPassword'] === $this->DefaultPassword) {
                        $RowInfo['AccWarnings'] .= '<br /><div class="txtRd">' . $this->Loader->L10N->getString('state_default_password') . '</div>';
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
                        $RowInfo['AccWarnings'] .= '<br /><div class="txtRd">' . $this->Loader->L10N->getString('state_password_not_valid') . '</div>';
                    }

                    $RowInfo['AccID'] = bin2hex($RowInfo['AccUsername']);
                    $RowInfo['AccUsername'] = htmlentities($RowInfo['AccUsername']);
                    $FE['Accounts'] .= $this->Loader->parse(
                        $this->Loader->L10N->Data,
                        $this->Loader->parse($RowInfo, $AccountsRow)
                    );
                }
                unset($RowInfo);
            }

            if ($FE['ASYNC']) {
                /** Send output (async). */
                echo $FE['state_msg'];
            } else {
                /** Parse output. */
                $FE['FE_Content'] = $this->Loader->parse(
                    $this->Loader->L10N->Data,
                    $this->Loader->parse($FE, $this->Loader->readFileBlocks($this->getAssetPath('_accounts.html')))
                );

                /** Send output. */
                echo $this->sendOutput($FE);
            }
            return;
        }

        /** Configuration. */
        if ($Page === 'config' && $this->Permissions === 1) {
            /** Page initial prepwork. */
            $this->initialPrepwork($FE, $this->Loader->L10N->getString('link_config'), $this->Loader->L10N->getString('tip_config'));

            /** Append number localisation JS. */
            $FE['JS'] .= $this->numberJS() . "\n";

            /** Directive template. */
            $ConfigurationRow = $this->Loader->readFileBlocks($this->getAssetPath('_config_row.html'));

            /** Flag for modified configuration. */
            $ConfigurationModified = false;

            $FE['Indexes'] = '<ul class="pieul">';

            /** Generate entries for display and regenerate configuration if any changes were submitted. */
            $FE['ConfigFields'] = sprintf(
                '<style>.showlink::before,.hidelink::before{content:"➖";display:inline-block;margin-%1$s:6px}.hidelink::before{transform:rotate(%2$s)}</style>',
            $FE['FE_Align_Reverse'], $FE['45deg']);

            /** Iterate through configuration defaults. */
            foreach ($this->Loader->ConfigurationDefaults as $CatKey => $CatValue) {
                if (!is_array($CatValue)) {
                    continue;
                }
                if ($CatInfo = $this->Loader->L10N->getString('config_' . $CatKey)) {
                    $CatInfo = '<br /><em>' . $CatInfo . '</em>';
                }
                $FE['ConfigFields'] .= sprintf(
                    '<table><tr><td class="ng2"><div id="%1$s-container" class="s">' .
                    '<a class="showlink" id="%1$s-showlink" href="#%1$s-container" onclick="javascript:showid(\'%1$s-hidelink\');hideid(\'%1$s-showlink\');show(\'%1$s-row\')">%1$s</a>' .
                    '<a class="hidelink" id="%1$s-hidelink" %2$s href="#" onclick="javascript:showid(\'%1$s-showlink\');hideid(\'%1$s-hidelink\');hide(\'%1$s-row\')">%1$s</a>' .
                    "%3\$s</div></td></tr></table>\n<span class=\"%1\$s-row\" %2\$s><table>\n",
                $CatKey, 'style="display:none"', $CatInfo);
                $CatData = '';
                foreach ($CatValue as $DirKey => $DirValue) {
                    $ThisDir = ['Preview' => '', 'Trigger' => '', 'FieldOut' => '', 'CatKey' => $CatKey];
                    if (empty($DirValue['type']) || !isset($this->Loader->Configuration[$CatKey][$DirKey])) {
                        continue;
                    }
                    $ThisDir['DirLangKey'] = 'config_' . $CatKey . '_' . $DirKey;
                    $ThisDir['DirLangKeyOther'] = $ThisDir['DirLangKey'] . '_other';
                    $ThisDir['DirName'] = $this->ltrInRtf($CatKey . '➡' . $DirKey);
                    $ThisDir['Friendly'] = $this->Loader->L10N->getString($ThisDir['DirLangKey'] . '_label') ?: $DirKey;
                    $CatData .= sprintf(
                        '<li><a onclick="javascript:showid(\'%1$s-hidelink\');hideid(\'%1$s-showlink\');show(\'%1$s-row\')" href="#%2$s">%3$s</a></li>',
                    $CatKey, $ThisDir['DirLangKey'], $ThisDir['Friendly']);
                    $ThisDir['DirLang'] =
                        $this->Loader->L10N->getString($ThisDir['DirLangKey']) ?:
                        $this->Loader->L10N->getString('config_' . $CatKey) ?:
                        $this->Loader->L10N->getString('response_error');
                    if (!empty($DirValue['experimental'])) {
                        $ThisDir['DirLang'] = '<code class="exp">' . $this->Loader->L10N->getString('config_experimental') . '</code> ' . $ThisDir['DirLang'];
                    }
                    $ThisDir['autocomplete'] = empty($DirValue['autocomplete']) ? '' : sprintf(
                        ' autocomplete="%s"',
                        $DirValue['autocomplete']
                    );
                    if (isset($_POST[$ThisDir['DirLangKey']])) {
                        if (in_array($DirValue['type'], ['bool', 'float', 'int', 'kb', 'string', 'timezone', 'email', 'url'], true)) {
                            $this->Loader->autoType($_POST[$ThisDir['DirLangKey']], $DirValue['type']);
                        }
                        if (!preg_match('/[^\x20-\xff"\']/', $_POST[$ThisDir['DirLangKey']]) && (
                            !isset($DirValue['choices']) ||
                            isset($DirValue['choices'][$_POST[$ThisDir['DirLangKey']]])
                        )) {
                            $ConfigurationModified = true;
                            $this->Loader->Configuration[$CatKey][$DirKey] = $_POST[$ThisDir['DirLangKey']];
                        } elseif (
                            !empty($DirValue['allow_other']) &&
                            $_POST[$ThisDir['DirLangKey']] === 'Other' &&
                            isset($_POST[$ThisDir['DirLangKeyOther']]) &&
                            !preg_match('/[^\x20-\xff"\']/', $_POST[$ThisDir['DirLangKeyOther']])
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
                            if (!empty($_POST[$ThisDir['DirLangKey'] . '_' . $DirValue['ThisChoiceKey']])) {
                                $DirValue['Posts'][] = $DirValue['ThisChoiceKey'];
                            }
                        }
                        $DirValue['Posts'] = implode(',', $DirValue['Posts']) ?: '';
                        if (
                            !empty($_POST['updatingConfig']) &&
                            $this->Loader->Configuration[$CatKey][$DirKey] !== $DirValue['Posts']
                        ) {
                            $ConfigurationModified = true;
                            $this->Loader->Configuration[$CatKey][$DirKey] = $DirValue['Posts'];
                        }
                    }
                    if (isset($DirValue['preview'])) {
                        $ThisDir['Preview'] = ($DirValue['preview'] === 'allow_other') ? '' : ' = <span id="' . $ThisDir['DirLangKey'] . '_preview"></span>';
                        $ThisDir['Trigger'] = ' onchange="javascript:' . $ThisDir['DirLangKey'] . '_function();" onkeyup="javascript:' . $ThisDir['DirLangKey'] . '_function();"';
                        if ($DirValue['preview'] === 'kb') {
                            $ThisDir['Preview'] .= sprintf(
                                    '<script type="text/javascript">function %1$s_function(){var e=%7$s?%7$s(' .
                                    '\'%1$s_field\').value:%8$s&&!%7$s?%8$s.%1$s_field.value:\'\',z=e.replace' .
                                    '(/o$/i,\'b\').substr(-2).toLowerCase(),y=\'kb\'==z?1:\'mb\'==z?1024:\'gb' .
                                    '\'==z?1048576:\'tb\'==z?1073741824:\'b\'==e.substr(-1)?.0009765625:1,e=e' .
                                    '.replace(/[^0-9]*$/i,\'\'),e=isNaN(e)?0:e*y,t=0>e?\'0 %2$s\':1>e?nft((10' .
                                    '24*e).toFixed(0))+\' %2$s\':1024>e?nft((1*e).toFixed(2))+\' %3$s\':10485' .
                                    '76>e?nft((e/1024).toFixed(2))+\' %4$s\':1073741824>e?nft((e/1048576).toF' .
                                    'ixed(2))+\' %5$s\':nft((e/1073741824).toFixed(2))+\' %6$s\';%7$s?%7$s(\'' .
                                    '%1$s_preview\').innerHTML=t:%8$s&&!%7$s?%8$s.%1$s_preview.innerHTML=t:\'' .
                                    '\'};%1$s_function();</script>',
                                $ThisDir['DirLangKey'],
                                $this->Loader->L10N->getPlural(0, 'field_size_bytes'),
                                $this->Loader->L10N->getString('field_size_KB'),
                                $this->Loader->L10N->getString('field_size_MB'),
                                $this->Loader->L10N->getString('field_size_GB'),
                                $this->Loader->L10N->getString('field_size_TB'),
                                'document.getElementById',
                                'document.all'
                            );
                        } elseif ($DirValue['preview'] === 'seconds') {
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
                                $this->Loader->L10N->getString('previewer_years'),
                                $this->Loader->L10N->getString('previewer_months'),
                                $this->Loader->L10N->getString('previewer_weeks'),
                                $this->Loader->L10N->getString('previewer_days'),
                                $this->Loader->L10N->getString('previewer_hours'),
                                $this->Loader->L10N->getString('previewer_minutes'),
                                $this->Loader->L10N->getString('previewer_seconds'),
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
                                $this->Loader->L10N->getString('previewer_years'),
                                $this->Loader->L10N->getString('previewer_months'),
                                $this->Loader->L10N->getString('previewer_weeks'),
                                $this->Loader->L10N->getString('previewer_days'),
                                $this->Loader->L10N->getString('previewer_hours'),
                                $this->Loader->L10N->getString('previewer_minutes'),
                                $this->Loader->L10N->getString('previewer_seconds'),
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
                                $this->Loader->L10N->getString('previewer_years'),
                                $this->Loader->L10N->getString('previewer_months'),
                                $this->Loader->L10N->getString('previewer_weeks'),
                                $this->Loader->L10N->getString('previewer_days'),
                                $this->Loader->L10N->getString('previewer_hours'),
                                $this->Loader->L10N->getString('previewer_minutes'),
                                $this->Loader->L10N->getString('previewer_seconds'),
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
                        }
                    }
                    if ($DirValue['type'] === 'timezone') {
                        $DirValue['choices'] = ['SYSTEM' => $this->Loader->L10N->getString('field_system_timezone')];
                        foreach (array_unique(\DateTimeZone::listIdentifiers()) as $DirValue['ChoiceValue']) {
                            $DirValue['choices'][$DirValue['ChoiceValue']] = $DirValue['ChoiceValue'];
                        }
                    }
                    if (isset($DirValue['choices'])) {
                        if ($DirValue['type'] !== 'checkbox') {
                            $ThisDir['FieldOut'] = sprintf(
                                '<select class="auto" style="text-transform:capitalize" name="%1$s" id="%1$s_field"%2$s>',
                                $ThisDir['DirLangKey'],
                                $ThisDir['Trigger']
                            );
                        }
                        foreach ($DirValue['choices'] as $ChoiceKey => $ChoiceValue) {
                            if (isset($DirValue['choice_filter'])) {
                                if (
                                    !is_string($ChoiceValue) ||
                                    (method_exists($this, $DirValue['choice_filter']) && !$this->{$DirValue['choice_filter']}($ChoiceKey, $ChoiceValue))
                                ) {
                                    continue;
                                }
                            }
                            $ChoiceValue = $this->Loader->timeFormat($this->Loader->Time, $ChoiceValue);
                            if (strpos($ChoiceValue, '{') !== false) {
                                $ChoiceValue = $this->Loader->parse($this->Loader->L10N->Data, $ChoiceValue);
                            }
                            if ($DirValue['type'] === 'checkbox') {
                                $ThisDir['FieldOut'] .= sprintf(
                                    '<input type="checkbox" class="auto" name="%1$s" id="%1$s"%2$s /><label for="%1$s" class="s">%3$s</label><br />',
                                    $ThisDir['DirLangKey'] . '_' . $ChoiceKey,
                                    $this->Loader->inCsv($ChoiceKey, $this->Loader->Configuration[$CatKey][$DirKey]) ? ' checked' : '',
                                    $ChoiceValue
                                );
                            } else {
                                foreach (['response_', 'label_', 'field_'] as $ChoicePrefix) {
                                    if (array_key_exists($ChoicePrefix . $ChoiceValue, $this->Loader->L10N->Data)) {
                                        $ChoiceValue = $this->Loader->L10N->getString($ChoicePrefix . $ChoiceValue);
                                        break;
                                    }
                                }
                                $ThisDir['FieldOut'] .= sprintf(
                                    '<option style="text-transform:capitalize" value="%1$s"%2$s>%3$s</option>',
                                    $ChoiceKey,
                                    $ChoiceKey === $this->Loader->Configuration[$CatKey][$DirKey] ? ' selected' : '',
                                    $ChoiceValue
                                );
                            }
                        }
                        if ($DirValue['type'] !== 'checkbox') {
                            $ThisDir['SelectOther'] = !isset($DirValue['choices'][$this->Loader->Configuration[$CatKey][$DirKey]]);
                            $ThisDir['FieldOut'] .= empty($DirValue['allow_other']) ? '</select>' : sprintf(
                                '<option value="Other"%1$s>%2$s</option></select> <input type="text"%3$s class="auto" name="%4$s" id="%4$s_field" value="%5$s" />',
                                $ThisDir['SelectOther'] ? ' selected' : '',
                                $this->Loader->L10N->getString('label_other'),
                                $ThisDir['SelectOther'] ? '' : ' style="display:none"',
                                $ThisDir['DirLangKeyOther'],
                                $this->Loader->Configuration[$CatKey][$DirKey]
                            );
                        }
                    } elseif ($DirValue['type'] === 'bool') {
                        $ThisDir['FieldOut'] = sprintf(
                                '<select class="auto" name="%1$s" id="%1$s_field"%2$s>' .
                                '<option value="true"%5$s>%3$s</option><option value="false"%6$s>%4$s</option>' .
                                '</select>',
                            $ThisDir['DirLangKey'],
                            $ThisDir['Trigger'],
                            $this->Loader->L10N->getString('field_true'),
                            $this->Loader->L10N->getString('field_false'),
                            ($this->Loader->Configuration[$CatKey][$DirKey] ? ' selected' : ''),
                            ($this->Loader->Configuration[$CatKey][$DirKey] ? '' : ' selected')
                        );
                    } elseif (in_array($DirValue['type'], ['float', 'int'], true)) {
                        $ThisDir['FieldOut'] = sprintf(
                            '<input type="number" name="%1$s" id="%1$s_field" value="%2$s"%3$s%4$s%5$s />',
                            $ThisDir['DirLangKey'],
                            $this->Loader->Configuration[$CatKey][$DirKey],
                            (isset($DirValue['step']) ? ' step="' . $DirValue['step'] . '"' : ''),
                            $ThisDir['Trigger'],
                            ($DirValue['type'] === 'int' ? ' inputmode="numeric"' : '')
                        );
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
                    } else {
                        $ThisDir['FieldOut'] = sprintf(
                            '<input type="text" name="%1$s" id="%1$s_field" value="%2$s"%3$s%4$s />',
                            $ThisDir['DirLangKey'],
                            $this->Loader->Configuration[$CatKey][$DirKey],
                            $ThisDir['autocomplete'],
                            $ThisDir['Trigger']
                        );
                    }
                    $ThisDir['FieldOut'] .= $ThisDir['Preview'];
                    if (!empty($DirValue['See also']) && is_array($DirValue['See also'])) {
                        $ThisDir['FieldOut'] .= sprintf("\n<br /><br />%s<ul>\n", $this->Loader->L10N->getString('label_see_also'));
                        foreach ($DirValue['See also'] as $RefKey => $RefLink) {
                            $ThisDir['FieldOut'] .= sprintf('<li><a dir="ltr" href="%s">%s</a></li>', $RefLink, $RefKey);
                        }
                        $ThisDir['FieldOut'] .= "\n</ul>";
                    }
                    $FE['ConfigFields'] .= $this->Loader->parse(
                        $this->Loader->L10N->Data,
                        $this->Loader->parse($ThisDir, $ConfigurationRow)
                    );
                }
                $CatKeyFriendly = $this->Loader->L10N->getString('config_' . $CatKey . '_label') ?: $CatKey;
                $FE['Indexes'] .= sprintf(
                    '<li><span class="comCat" style="cursor:pointer">%1$s</span><ul class="comSub">%2$s</ul></li>',
                    $CatKeyFriendly,
                    $CatData
                );
                $FE['ConfigFields'] .= "</table></span>\n";
            }

            /** Update the currently active configuration file if any changes were made. */
            if ($ConfigurationModified) {
                if ($this->Loader->updateConfiguration()) {
                    $FE['state_msg'] = $this->Loader->L10N->getString('response_configuration_updated');
                } else {
                    $FE['state_msg'] = $this->Loader->L10N->getString('response_failed_to_update');
                }
            }

            $FE['Indexes'] .= '</ul>';

            /** Parse output. */
            $FE['FE_Content'] = $this->Loader->parse(
                $this->Loader->L10N->Data,
                $this->Loader->parse($FE, $this->Loader->readFileBlocks($this->getAssetPath('_config.html')))
            ) . $MenuToggle;

            /** Send output. */
            echo $this->sendOutput($FE);
            return;
        }

        /** Cache data. */
        if ($Page === 'cache-data' && $this->Permissions === 1) {
            /** Page initial prepwork. */
            $this->initialPrepwork($FE, $this->Loader->L10N->getString('link_cache_data'), $this->Loader->L10N->getString('tip_cache_data'));

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
                    "function cdd(d,n){window.cdi=d,window.do='delete',$('POST','',['phpmusse" .
                    "l-form-target','cdi','do'],null,function(o){hideid(d+'Container')})}wind" .
                    "ow['phpmussel-form-target']='cache-data';window['phpmussel-form-target']='cache-data';";

                /** To be populated by the cache data. */
                $FE['CacheData'] = '';

                /** Array of all cache items from all sources. */
                $CacheArray = [];

                /** Get cache index data. */
                if ($this->Loader->Cache->Using) {
                    foreach ($this->Loader->Cache->getAllEntries() as $ThisCacheName => $ThisCacheItem) {
                        if (isset($ThisCacheItem['Time']) && $ThisCacheItem['Time'] > 0 && $ThisCacheItem['Time'] < $this->Loader->Time) {
                            continue;
                        }
                        $this->Loader->arrayify($ThisCacheItem);
                        $CacheArray[$this->Loader->Cache->Using][$ThisCacheName] = $ThisCacheItem;
                    }
                    unset($ThisCacheName, $ThisCacheItem);
                }

                /** Begin processing all cache items from all sources. */
                foreach ($CacheArray as $CacheSourceName => $CacheSourceData) {
                    if (empty($CacheSourceData)) {
                        continue;
                    }
                    $FE['CacheData'] .= sprintf(
                        '<div class="ng1" id="__Container"><span class="s">%s – (<span style="cursor:pointer" onclick="javascript:cdd(\'__\')"><code class="s">%s</code></span>)</span><br /><br /><ul class="pieul">%s</ul></div>',
                        $CacheSourceName,
                        $this->Loader->L10N->getString('field_clear_all'),
                        $this->arrayToClickableList($CacheSourceData, 'cdd', 0, $CacheSourceName)
                    );
                }
                unset($CacheSourceData, $CacheSourceName, $CacheArray);

                /** Cache is empty. */
                if (!$FE['CacheData']) {
                    $FE['CacheData'] = '<div class="ng1"><span class="s">' . $this->Loader->L10N->getString('state_cache_is_empty') . '</span></div>';
                }

                /** Parse output. */
                $FE['FE_Content'] = $this->Loader->parse(
                    $this->Loader->L10N->Data,
                    $this->Loader->parse($FE, $this->Loader->readFileBlocks($this->getAssetPath('_cache.html')))
                ) . $MenuToggle;

                /** Send output. */
                echo $this->sendOutput($FE);
            }
            return;
        }

        /** Upload Test. */
        if ($Page === 'upload-test' && $this->Permissions === 1) {
            /** Page initial prepwork. */
            $this->initialPrepwork($FE, $this->Loader->L10N->getString('link_upload_test'), $this->Loader->L10N->getString('tip_upload_test'), false);

            /** Append upload test JS. */
            $FE['JS'] .=
                'var x=1,a=\'<input type="file" name="upload_test[]" value="" />\',more=f' .
                "unction(){var e='field'+x,t=document.createElement('div');t.setAttribute" .
                "('class','spanner'),t.setAttribute('id',e),t.setAttribute('style','opaci" .
                "ty:0.0;animation:UplT 2.0s ease 0s 1 normal'),document.getElementById('u" .
                "pload_fields').appendChild(t),document.getElementById(e).innerHTML=a,set" .
                "Timeout(function(){document.getElementById(e).style.opacity='1.0'},1999)" .
                ',x++};';

            $FE['MaxFilesize'] = $this->Loader->readBytes($this->Loader->Configuration['files']['filesize_limit']);

            /** Parse output. */
            $FE['FE_Content'] = $this->Loader->parse(
                $this->Loader->L10N->Data,
                $this->Loader->parse($FE, $this->Loader->readFileBlocks($this->getAssetPath('_upload_test.html')))
            );

            /** Send output. */
            echo $this->sendOutput($FE);
            return;
        }

        /** Quarantine. */
        if ($Page === 'quarantine' && $this->Permissions === 1) {
            /** Page initial prepwork. */
            $this->initialPrepwork($FE, $this->Loader->L10N->getString('link_quarantine'), $this->Loader->L10N->getString('tip_quarantine'));

            /** Display how to enable quarantine if currently disabled. */
            if (!$this->Loader->Configuration['quarantine']['quarantine_key']) {
                $FE['state_msg'] .= '<span class="txtRd">' . $this->Loader->L10N->getString('tip_quarantine_disabled') . '</span><br />';
            }

            /** Generate confirm button. */
            $FE['Confirm-DeleteAll'] = $this->generateConfirm($this->Loader->L10N->getString('field_delete_all'), 'quarantineForm');

            /** Append necessary quarantine JS. */
            $FE['JS'] .= "function qOpt(e){b=document.getElementById(e+'-S'),'delete-file'==b.value?hideid(e):showid(e)}\n";

            /** A form was submitted. */
            if (
                !empty($_POST['qfu']) &&
                !empty($_POST['do']) &&
                !is_dir($this->Loader->QuarantinePath . $_POST['qfu']) &&
                is_readable($this->Loader->QuarantinePath . $_POST['qfu'])
            ) {
                /** Delete a file. */
                if ($_POST['do'] === 'delete-file') {

                    $FE['state_msg'] .= '<code>' . $_POST['qfu'] . '</code> ' . $this->Loader->L10N->getString(
                        unlink($this->Loader->QuarantinePath . $_POST['qfu']) ? 'response_file_deleted' : 'response_failed_to_delete'
                    ) . '<br />';

                /** Download or restore a file. */
                } elseif ($_POST['do'] === 'download-file' || $_POST['do'] === 'restore-file') {

                    if (empty($_POST['qkey'])) {
                        $FE['state_msg'] .= '<code>' . $_POST['qfu'] . '</code> ' . $this->Loader->L10N->getString('response_restore_error_2') . '<br />';
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
                            $FE['state_msg'] .= '<code>' . $_POST['qfu'] . '.restored</code> ' . $this->Loader->L10N->getString('response_file_restored') . '<br />';
                        }

                        /** Corrupted file! */
                        elseif ($this->InstanceCache['RestoreStatus'] === 2) {
                            $FE['state_msg'] .= '<code>' . $_POST['qfu'] . '</code> ' . $this->Loader->L10N->getString('response_restore_error_1') . '<br />';
                        }

                        /** Incorrect quarantine key! */
                        else {
                            $FE['state_msg'] .= '<code>' . $_POST['qfu'] . '</code> ' . $this->Loader->L10N->getString('response_restore_error_2') . '<br />';
                        }

                        /** Cleanup. */
                        unset($this->InstanceCache['RestoreStatus'], $Restored);
                    }
                }
            }

            /** Delete all files in quarantine. */
            $DeleteMode = !empty($_POST['DeleteAll']);

            /** Template for quarantine files row. */
            $QuarantineRow = $this->Loader->readFileBlocks($this->getAssetPath('_quarantine_row.html'));

            /** Fetch quarantine data array. */
            $FilesInQuarantine = $this->quarantineRecursiveList($DeleteMode);

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
                $FE['FilesInQuarantine'] .= $this->Loader->parse(
                    $this->Loader->L10N->Data,
                    $this->Loader->parse($FE, $this->Loader->parse($ThisFile, $QuarantineRow))
                );
            }

            /** Cleanup. */
            unset($ThisFile, $FilesInQuarantineCount, $FilesInQuarantine);

            /** Parse output. */
            $FE['FE_Content'] = $this->Loader->parse(
                $this->Loader->L10N->Data,
                $this->Loader->parse($FE, $this->Loader->readFileBlocks($this->getAssetPath('_quarantine.html')))
            );

            /** Send output. */
            echo $this->sendOutput($FE);
            return;
        }

        /** Signature information. */
        if ($Page === 'siginfo' && $this->Permissions === 1) {
            /** Page initial prepwork. */
            $this->initialPrepwork($FE, $this->Loader->L10N->getString('link_siginfo'), $this->Loader->L10N->getString('tip_siginfo'));

            /** Append number localisation JS. */
            $FE['JS'] .= $this->numberJS() . "\n";

            $FE['InfoRows'] = '';
            $FE['SigInfoMenuOptions'] = '';

            /** Process signature files and fetch relevant values. */
            $this->signatureInformationHandler($FE['InfoRows'], $FE['SigInfoMenuOptions']);

            /** Calculate and append page load time, and append totals. */
            $FE['ProcTime'] = microtime(true) - $_SERVER['REQUEST_TIME_FLOAT'];
            $FE['ProcTime'] = '<div class="s">' . sprintf(
                $this->Loader->L10N->getPlural($FE['ProcTime'], 'state_loadtime'),
                $this->NumberFormatter->format($FE['ProcTime'], 3)
            ) . '</div>';

            /** Parse output. */
            $FE['FE_Content'] = $this->Loader->parse(
                $this->Loader->L10N->Data,
                $this->Loader->parse($FE, $this->Loader->readFileBlocks($this->getAssetPath('_siginfo.html')))
            );

            /** Send output. */
            echo $this->sendOutput($FE);
            return;
        }

        /** Statistics. */
        if ($Page === 'statistics' && $this->Permissions === 1) {
            /** Page initial prepwork. */
            $this->initialPrepwork($FE, $this->Loader->L10N->getString('link_statistics'), $this->Loader->L10N->getString('tip_statistics'), false);

            /** Display how to enable statistics if currently disabled. */
            if (!$this->Loader->Configuration['core']['statistics']) {
                $FE['state_msg'] .= '<span class="txtRd">' . $this->Loader->L10N->getString('tip_statistics_disabled') . '</span><br />';
            }

            /** Generate confirm button. */
            $FE['Confirm-ClearAll'] = $this->generateConfirm($this->Loader->L10N->getString('field_clear_all'), 'statForm');

            /** Fetch statistics cache data. */
            if ($this->Loader->InstanceCache['Statistics'] = ($this->Loader->Cache->getEntry('Statistics') ?: [])) {
                if (is_string($this->Loader->InstanceCache['Statistics'])) {
                    unserialize($this->Loader->InstanceCache['Statistics']) ?: [];
                }
            }

            /** Clear statistics. */
            if (!empty($_POST['ClearStats'])) {
                $this->Loader->Cache->deleteEntry('Statistics');
                $this->Loader->InstanceCache['Statistics'] = [];
                $FE['state_msg'] .= $this->Loader->L10N->getString('response_statistics_cleared') . '<br />';
            }

            /** Statistics have been counted since... */
            $FE['Other-Since'] = '<span class="s">' . (
                empty($this->Loader->InstanceCache['Statistics']['Other-Since']) ? '-' : $this->Loader->timeFormat(
                    $this->Loader->InstanceCache['Statistics']['Other-Since'],
                    $this->Loader->Configuration['core']['time_format']
                )
            ) . '</span>';

            /** Fetch and process various statistics. */
            foreach ([
                'Web-Events',
                'Web-Scanned',
                'Web-Blocked',
                'Web-Quarantined',
                'CLI-Events',
                'CLI-Scanned',
                'CLI-Flagged',
                'API-Events',
                'API-Scanned',
                'API-Flagged'
            ] as $TheseStats) {
                $FE[$TheseStats] = '<span class="s">' . $this->NumberFormatter->format(
                    $this->Loader->InstanceCache['Statistics'][$TheseStats] ?? 0
                ) . '</span>';
            }

            /** Active signature files. */
            if (empty($this->Loader->Configuration['signatures']['active'])) {
                $FE['Other-Active'] = '<span class="txtRd">' . $this->NumberFormatter->format(0) . '</span>';
            } else {
                $FE['Other-Active'] = count(array_unique(array_filter(explode(',', $this->Loader->Configuration['signatures']['active']), function ($Item) {
                    return !empty($Item);
                })));
                $StatColour = $FE['Other-Active'] ? 'txtGn' : 'txtRd';
                $FE['Other-Active'] = '<span class="' . $StatColour . '">' . $this->NumberFormatter->format(
                    $FE['Other-Active']
                ) . '</span>';
            }

            /** Parse output. */
            $FE['FE_Content'] = $this->Loader->parse(
                $this->Loader->L10N->Data,
                $this->Loader->parse($FE, $this->Loader->readFileBlocks($this->getAssetPath('_statistics.html')))
            );

            /** Send output. */
            echo $this->sendOutput($FE);

            /** Cleanup. */
            unset($this->Loader->InstanceCache['Statistics']);
            return;
        }

        /** Logs. */
        if ($Page === 'logs' && ($this->Permissions === 1 || $this->Permissions === 2)) {
            /** Page initial prepwork. */
            $this->initialPrepwork($FE, $this->Loader->L10N->getString('link_logs'), $this->Loader->L10N->getString('tip_logs'), false);

            /** Parse output. */
            $FE['FE_Content'] = $this->Loader->parse(
                $this->Loader->L10N->Data,
                $this->Loader->parse($FE, $this->Loader->readFileBlocks($this->getAssetPath('_logs.html')))
            );

            /** Initialise array for fetching logs data. */
            $FE['LogFiles'] = ['Files' => $this->logsRecursiveList($this->AssetsPath), 'Out' => ''];

            /** Text mode switch link base. */
            $FE['TextModeSwitchLink'] = '';

            /** How to display the log data? */
            if (empty($this->QueryVariables['text-mode']) || $this->QueryVariables['text-mode'] === 'false') {
                $FE['TextModeLinks'] = 'false';
                $TextMode = false;
            } else {
                $FE['TextModeLinks'] = 'true';
                $TextMode = true;
            }

            /** Define log data. */
            if (empty($this->QueryVariables['logfile'])) {
                $FE['logfileData'] = $this->Loader->L10N->getString('logs_no_logfile_selected');
            } elseif (empty($FE['LogFiles']['Files'][$this->QueryVariables['logfile']])) {
                $FE['logfileData'] = $this->Loader->L10N->getString('logs_logfile_doesnt_exist');
            } else {
                $FE['TextModeSwitchLink'] .= '?phpmussel-page=logs&logfile=' . $this->QueryVariables['logfile'] . '&text-mode=';
                if (strtolower(substr($this->QueryVariables['logfile'], -3)) === '.gz') {
                    $FE['logfileData'] = $this->Loader->readFileBlocksGZ($this->QueryVariables['logfile']);
                } else {
                    $FE['logfileData'] = $this->Loader->readFileBlocks($this->QueryVariables['logfile']);
                }
                $FE['logfileData'] = $TextMode ? str_replace(
                    ['<', '>', "\r", "\n"], ['&lt;', '&gt;', '', "<br />\n"], $FE['logfileData']
                ) : str_replace(
                    ['<', '>', "\r"], ['&lt;', '&gt;', ''], $FE['logfileData']
                );
                $FE['mod_class_nav'] = ' big';
                $FE['mod_class_right'] = ' extend';
            }
            if (empty($FE['mod_class_nav'])) {
                $FE['mod_class_nav'] = ' extend';
                $FE['mod_class_right'] = ' big';
            }
            if (empty($FE['TextModeSwitchLink'])) {
                $FE['TextModeSwitchLink'] .= '?phpmussel-page=logs&text-mode=';
            }

            /** Text mode switch link formatted. */
            $FE['TextModeSwitchLink'] = sprintf(
                $this->Loader->L10N->getString('link_textmode'),
                $FE['TextModeSwitchLink']
            );

            /** Prepare log data formatting. */
            if (!$TextMode) {
                $FE['logfileData'] = '<textarea readonly>' . $FE['logfileData'] . '</textarea>';
            } else {
                $this->formatter($FE['logfileData']);
            }

            /** Process logs list. */
            foreach ($FE['LogFiles']['Files'] as $Filename => $Filesize) {
                $FE['LogFiles']['Out'] .= sprintf(
                    '      <a href="?phpmussel-page=logs&logfile=%1$s&text-mode=%3$s">%1$s</a> – %2$s<br />',
                    $Filename ?? '',
                    $Filesize ?? '',
                    $FE['TextModeLinks'] ?? ''
                ) . "\n";
            }

            /** Calculate page load time (useful for debugging). */
            $FE['ProcessTime'] = microtime(true) - $_SERVER['REQUEST_TIME_FLOAT'];
            $FE['ProcessTime'] = '<br />' . sprintf(
                $this->Loader->L10N->getPlural($FE['ProcessTime'], 'state_loadtime'),
                $this->NumberFormatter->format($FE['ProcessTime'], 3)
            );

            /** Set logfile list or no logfiles available message. */
            $FE['LogFiles'] = $FE['LogFiles']['Out'] ?: $this->Loader->L10N->getString('logs_no_logfiles_available');

            /** Send output. */
            echo $this->sendOutput($FE);
            return;
        }
    }

    /**
     * Format filesize information.
     *
     * @param int $Filesize
     */
    private function formatFilesize(int &$Filesize)
    {
        $Scale = ['field_size_bytes', 'field_size_KB', 'field_size_MB', 'field_size_GB', 'field_size_TB'];
        $Iterate = 0;
        $Filesize = (int)$Filesize;
        while ($Filesize > 1024) {
            $Filesize = $Filesize / 1024;
            $Iterate++;
            if ($Iterate > 4) {
                break;
            }
        }
        $Filesize = $this->NumberFormatter->format($Filesize, ($Iterate === 0) ? 0 : 2) . ' ' . $this->Loader->L10N->getPlural($Filesize, $Scale[$Iterate]);
    }

    /**
     * Generates a list of all currently existing logs.
     *
     * @return array The logs list.
     */
    public function logsRecursiveList(): array
    {
        $Arr = [];
        foreach ($this->Loader->InstanceCache['LogPaths'] as $LogPath) {
            if ((strpos($LogPath, '{') === false && strpos($LogPath, '}') === false)) {
                if (is_file($LogPath) && is_readable($LogPath)) {
                    $Arr[] = $LogPath;
                }
                continue;
            }
            foreach ($this->Loader->resolvePaths($LogPath) as $Item) {
                $Arr[] = $Item;
            }
        }
        $Items = [];
        foreach ($Arr as $Item) {
            $Items[$Item] = filesize($Item);
            $this->formatFilesize($Items[$Item]);
        }
        ksort($Items);
        return $Items;
    }

    /**
     * Filter the available language options provided by the configuration page on
     * the basis of the availability of the corresponding language files.
     *
     * @param string $ChoiceKey Language code.
     * @return bool Valid/Invalid.
     */
    private function filterL10N(string $ChoiceKey): bool
    {
        return is_readable($this->L10NPath . $ChoiceKey . '.yml');
    }

    /**
     * Filter the available hash algorithms provided by the configuration page on
     * the basis of their availability.
     *
     * @param string $ChoiceKey Hash algorithm.
     * @return bool Available/Unavailable.
     */
    private function filterByDefined(string $ChoiceKey)
    {
        return defined($ChoiceKey);
    }

    /**
     * Filter the available theme options provided by the configuration page on
     * the basis of their availability.
     *
     * @param string $ChoiceKey Theme ID.
     * @return bool Valid/Invalid.
     */
    private function filterTheme(string $ChoiceKey): bool
    {
        if ($ChoiceKey === 'default') {
            return true;
        }
        $Path = $this->AssetsPath . 'fe_assets' . DIRECTORY_SEPARATOR . $ChoiceKey . '/';
        return (file_exists($Path . 'frontend.css') || file_exists($this->AssetsPath . 'template_' . $ChoiceKey . '.html'));
    }

    /**
     * Get the appropriate path for a specified asset as per the defined theme.
     *
     * @param string $Asset The asset filename.
     * @param bool $CanFail Is failure acceptable? (Default: False)
     * @throws Exception if the asset can't be found.
     * @return string The asset path.
     */
    private function getAssetPath(string $Asset, bool $CanFail = false): string
    {
        /** Guard against unsafe paths. */
        if (preg_match('~[^\da-z._]~i', $Asset)) {
            return '';
        }

        /** Non-default assets. */
        if (
            $this->Loader->Configuration['frontend']['theme'] !== 'default' &&
            is_readable($this->AssetsPath . $this->Loader->Configuration['frontend']['theme'] . DIRECTORY_SEPARATOR . $Asset)
        ) {
            return $this->AssetsPath . $this->Loader->Configuration['frontend']['theme'] . DIRECTORY_SEPARATOR . $Asset;
        }

        /** Default assets. */
        if (is_readable($this->AssetsPath . 'default' . DIRECTORY_SEPARATOR . $Asset)) {
            return $this->AssetsPath . 'default' . DIRECTORY_SEPARATOR . $Asset;
        }

        /** Failure. */
        if ($CanFail) {
            return '';
        }
        throw new \Exception('Asset not found');
    }

    /**
     * Generates JavaScript code for localising numbers locally.
     *
     * @return string The JavaScript code.
     */
    private function numberJS(): string
    {
        if ($this->NumberFormatter->ConversionSet === 'Western') {
            $ConvJS = 'return l10nd';
        } else {
            $ConvJS = 'var nls=[' . $this->NumberFormatter->getSetCSV(
                $this->NumberFormatter->ConversionSet
            ) . '];return nls[l10nd]||l10nd';
        }
        return sprintf(
            'function l10nn(l10nd){%4$s};function nft(r){var x=r.indexOf(\'.\')!=-1?' .
            '\'%1$s\'+r.replace(/^.*\./gi,\'\'):\'\',n=r.replace(/\..*$/gi,\'\').rep' .
            'lace(/[^0-9]/gi,\'\'),t=n.length;for(e=\'\',b=%5$d,i=1;i<=t;i++){b>%3$d' .
            '&&(b=1,e=\'%2$s\'+e);var e=l10nn(n.substring(t-i,t-(i-1)))+e;b++}var t=' .
            'x.length;for(y=\'\',b=1,i=1;i<=t;i++){var y=l10nn(x.substring(t-i,t-(i-' .
            '1)))+y}return e+y}',
            $this->NumberFormatter->DecimalSeparator,
            $this->NumberFormatter->GroupSeparator,
            $this->NumberFormatter->GroupSize,
            $ConvJS,
            $this->NumberFormatter->GroupOffset + 1
        );
    }

    /**
     * Quarantined file list generator (returns an array of quarantined files).
     *
     * @param bool $DeleteMode Whether to delete quarantined files when checking.
     * @return array An array of quarantined files.
     */
    private function quarantineRecursiveList(bool $DeleteMode = false): array
    {
        /** Guard against missing or unwritable quarantine directory. */
        if (!$this->Loader->QuarantinePath) {
            return [];
        }

        $Arr = [];
        $Key = -1;
        $Offset = strlen($this->Loader->QuarantinePath);
        $List = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($this->Loader->QuarantinePath), \RecursiveIteratorIterator::SELF_FIRST);
        foreach ($List as $Item => $List) {
            /** Skips if not a quarantined file. */
            if (!preg_match('~\.qfu$~i', $Item) || is_dir($Item) || !is_file($Item) || !is_readable($Item)) {
                continue;
            }

            /** Deletes all files in quarantine. */
            if ($DeleteMode) {
                $DeleteMe = substr($Item, $Offset);
                $FE['state_msg'] .= '<code>' . $DeleteMe . '</code> ' . $this->Loader->L10N->getString(
                    unlink($this->Loader->QuarantinePath . $DeleteMe) ? 'response_file_deleted' : 'response_failed_to_delete'
                ) . '<br />';
                continue;
            }

            $Key++;
            $Arr[$Key] = [
                'QFU-Name' => substr($Item, $Offset),
                'QFU-JS-ID' => substr($Item, $Offset, -4),
                'QFU-Size' => filesize($Item)
            ];
            $this->formatFilesize($Arr[$Key]['QFU-Size']);
            $Head = $this->Loader->readFileBlocks($Item, 256);

            /** Upload date/time. */
            $Arr[$Key]['Upload-Date'] = (
                ($DatePos = strpos($Head, 'Time/Date Uploaded: ')) !== false
            ) ? $this->Loader->timeFormat(
                (int)substr($Head, $DatePos + 20, 16),
                $this->Loader->Configuration['core']['time_format']
            ) : $this->Loader->L10N->getString('field_filetype_unknown');

            /** Upload origin. */
            $Arr[$Key]['Upload-Origin'] = (
                ($OriginStartPos = strpos($Head, 'Uploaded From: ')) !== false &&
                ($OriginEndPos = strpos($Head, ' ', $OriginStartPos + 15)) !== false
            ) ? substr($Head, $OriginStartPos + 15, $OriginEndPos - $OriginStartPos - 15) : $this->Loader->L10N->getString('field_filetype_unknown');

            /** If the phpMussel QFU (Quarantined File Upload) header isn't found, it probably isn't a quarantined file. */
            if (($HeadPos = strpos($Head, "\xa1phpMussel\x21")) !== false && (substr($Head, $HeadPos + 31, 1) === "\x01")) {
                $Head = substr($Head, $HeadPos);
                $Arr[$Key]['Upload-MD5'] = bin2hex(substr($Head, 11, 16));
                $Arr[$Key]['Upload-Size'] = $this->Loader->unpackSafe('l*', substr($Head, 27, 4));
                $Arr[$Key]['Upload-Size'] = isset($Arr[$Key]['Upload-Size'][1]) ? (int)$Arr[$Key]['Upload-Size'][1] : 0;
                $this->formatFilesize($Arr[$Key]['Upload-Size']);
            } else {
                $Arr[$Key]['Upload-MD5'] = $this->Loader->L10N->getString('field_filetype_unknown');
                $Arr[$Key]['Upload-Size'] = $this->Loader->L10N->getString('field_filetype_unknown');
            }

            /** Appends Virus Total search URL for this hash onto the hash. */
            if (strlen($Arr[$Key]['Upload-MD5']) === 32) {
                $Arr[$Key]['Upload-MD5'] = sprintf(
                    '<a href="https://www.virustotal.com/#/file/%1$s" rel="noopener noreferrer external">%1$s</a>',
                    $Arr[$Key]['Upload-MD5']
                );
            }
        }
        return $Arr;
    }

    /**
     * Restore a quarantined file (returns the restored file data or false on failure).
     *
     * @param string $File Path to the file to be restored.
     * @param string $Key The quarantine key used to quarantine the file.
     * @return string|bool The content of the restored file, or false on failure.
     */
    private function quarantineRestore(string $File, string $Key)
    {
        /** Set default value. */
        $this->InstanceCache['RestoreStatus'] = 1;

        /** Guard. */
        if (!$File || !$Key) {
            return false;
        }

        /** Fetch data. */
        $Data = $this->Loader->readFileBlocks($File);

        /** Fetch headers. */
        if (($HeadPos = strpos($Data, "\xa1phpMussel\x21")) === false || (substr($Data, $HeadPos + 31, 1) !== "\x01")) {
            $this->InstanceCache['RestoreStatus'] = 2;
            return false;
        }

        $Data = substr($Data, $HeadPos);
        $UploadMD5 = bin2hex(substr($Data, 11, 16));
        $UploadSize = $this->Loader->unpackSafe('l*', substr($Data, 27, 4));
        $UploadSize = isset($UploadSize[1]) ? (int)$UploadSize[1] : 0;
        $Data = substr($Data, 32);
        $DataLen = strlen($Data);
        if ($Key < 128) {
            $Key = $this->Loader->hexSafe(hash('sha512', $Key) . hash('whirlpool', $Key));
        }
        $KeyLen = strlen($Key);
        $Output = '';
        $Cycle = 0;
        while ($Cycle < $DataLen) {
            for ($Inner = 0; $Inner < $KeyLen; $Inner++, $Cycle++) {
                if (strlen($Output) >= $UploadSize) {
                    break 2;
                }
                $L = substr($Data, $Cycle, 1);
                $R = substr($Key, $Inner, 1);
                $Output .= ($L === false ? "\x00" : $L) ^ ($R === false ? "\x00" : $R);
            }
        }
        $Output = gzinflate($Output);
        if (empty($Output) || hash('md5', $Output) !== $UploadMD5) {
            $this->InstanceCache['RestoreStatus'] = 3;
            return false;
        }
        $this->InstanceCache['RestoreStatus'] = 0;
        return $Output;
    }

    /**
     * Normalise linebreaks.
     *
     * @param string $Data The data to normalise.
     */
    private function normaliseLinebreaks(string &$Data)
    {
        if (strpos($Data, "\r")) {
            $Data = (strpos($Data, "\r\n") !== false) ? str_replace("\r", '', $Data) : str_replace("\r", "\n", $Data);
        }
    }

    /**
     * Signature information handler.
     *
     * @param string $InfoRows Where to populate rows.
     * @param string $SigInfoMenuOptions Where to populate menu options.
     */
    private function signatureInformationHandler(string &$InfoRows, string &$SigInfoMenuOptions)
    {
        /** Guard. */
        if (!$this->Loader->loadShorthandData()) {
            $InfoRows = '<span class="s">' . $this->Loader->L10N->getString('response_error') . '</span>';
            return;
        }

        /** The currently active signature files. */
        $Active = array_unique(array_filter(explode(',', $this->Loader->Configuration['signatures']['active']), function ($Item) {
            return !empty($Item);
        }));

        /** Template for range rows. */
        $InfoRow = $this->Loader->readFileBlocks($this->getAssetPath('_siginfo_row.html'));

        /** Get list of vendor search patterns and metadata search pattern partials. */
        $Arr = [
            'Vendors' => $this->Loader->InstanceCache['shorthand.yml']['Vendor Search Patterns'],
            'SigTypes' => $this->Loader->InstanceCache['shorthand.yml']['Metadata Search Pattern Partials']
        ];

        /** Expand patterns for signature metadata. */
        foreach ($Arr['SigTypes'] as &$Type) {
            $Type = sprintf(
                '\x1a(?![\x80-\x8f])[\x0%1$s\x1%1$s\x2%1$s\x3%1$s\x4%1$s\x5%1$s\x6%1$s\x7%1$s\x8%1$s\x9%1$s\xa%1$s\xb%1$s\xc%1$s\xd%1$s\xe%1$s\ef%1$s].',
                $Type
            );
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

        /** Iterate through active signature files and append totals. */
        foreach ($Active as $File) {
            $File = (strpos($File, ':') === false) ? $File : substr($File, strpos($File, ':') + 1);
            $Data = $File && is_readable($this->Loader->SignaturesPath . $File) ? $this->Loader->readFileBlocks($this->Loader->SignaturesPath . $File) : '';
            if (substr($Data, 0, 9) !== 'phpMussel') {
                continue;
            }
            $Class = substr($Data, 9, 1);
            $Nibbles = $this->Scanner->splitNibble($Class);
            $Class = !isset($Classes[$Nibbles[0]]) ? [] : $Classes[$Nibbles[0]];
            $Totals['Files'][$File] = empty($Class[1]) ? substr_count($Data, ',') + 1 : preg_match_all('/' . $Class[1] . '\S+/', $Data);
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
                        $Counts = preg_match_all('/' . $Class[1] . $Pattern . '\S+/', $Data);
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
        unset($SubTotal, $Other, $Data, $File, $Counts, $Arr);

        /** Process totals. */
        foreach ($Subs as $Sub) {
            $Label = $this->Loader->L10N->getString('siginfo_sub_' . $Sub) ?: $Sub;
            $Class = 'sigtype_' . strtolower($Sub);
            $SigInfoMenuOptions .= "\n      <option value=\"" . $Class . '">' . $Label . '</option>';
            $ThisTable = '<span style="display:none" class="' . $Class . '"><table><tr><td class="center h4f" colspan="2"><span class="s">' . $Label . '</span></td></tr>' . "\n";
            arsort($Totals[$Sub]);
            foreach ($Totals[$Sub] as $Key => &$Total) {
                if (!$Total) {
                    continue;
                }
                $Total = $this->NumberFormatter->format($Total);
                $Label = $this->Loader->L10N->getString(
                    ($Key === 'Other' && $Sub === 'SigTypes') ? 'siginfo_key_Other_Metadata' : 'siginfo_key_' . $Key
                );
                if ($Key !== 'Total' && $Key !== 'Other') {
                    if (!$Label) {
                        $Label = sprintf($this->Loader->L10N->getString('siginfo_xkey'), $Key);
                    }
                    $CellClass = 'h3';
                } else {
                    $CellClass = 'r';
                }
                $ThisTable .= $this->Loader->parse(['x' => $CellClass, 'InfoType' => $Label, 'InfoNum' => $Total], $InfoRow);
            }
            $InfoRows .= $ThisTable . '</table></span>' . "\n";
        }
    }

    /**
     * Assign some basic variables (initial prepwork for most front-end pages).
     *
     * @param array $FE Any front-end variables needed for the output.
     * @param string $Title The page title.
     * @param string $Tips The page "tip" to include ("Hello username! Here you can...").
     * @param bool $JS Whether to include the standard front-end JavaScript boilerplate.
     */
    private function initialPrepwork(array &$FE, string $Title = '', string $Tips = '', bool $JS = true)
    {
        /** Set page title. */
        $FE['FE_Title'] = 'phpMussel – ' . $Title;

        /** Fetch and prepare username. */
        if ($Username = ($this->User ?? '')) {
            $Username = preg_replace('~^([^<>]+)<[^<>]+>$~', '\1', $Username);
            if (($AtChar = strpos($Username, '@')) !== false) {
                $Username = substr($Username, 0, $AtChar);
            }
        }

        /** Prepare page tooltip/description. */
        $FE['FE_Tip'] = $this->Loader->parse(['username' => $Username], $Tips);

        /** Load main front-end JavaScript data. */
        $FE['JS'] = $JS ? $this->Loader->readFileBlocks($this->getAssetPath('scripts.js')) : '';
    }

    /**
     * Send page output for front-end pages (plus some other final prepwork).
     *
     * @param array $FE Any front-end variables needed for the output.
     * @return string Page output.
     */
    private function sendOutput(array &$FE): string
    {
        if ($FE['JS']) {
            $FE['JS'] = "\n<script type=\"text/javascript\">" . $FE['JS'] . '</script>';
        }
        return $this->Loader->parse($this->Loader->L10N->Data, $this->Loader->parse($FE, $FE['Template']));
    }

    /**
     * Generates JavaScript snippets for confirmation prompts for front-end actions.
     *
     * @param string $Action The action being taken to be confirmed.
     * @param string $Form The ID of the form to be submitted when the action is confirmed.
     * @return string The JavaScript snippet.
     */
    private function generateConfirm(string $Action, string $Form): string
    {
        $Confirm = str_replace(["'", '"'], ["\'", '\x22'], sprintf($this->Loader->L10N->getString('confirm_action'), $Action));
        return 'javascript:confirm(\'' . $Confirm . '\')&&document.getElementById(\'' . $Form . '\').submit()';
    }

    /**
     * A quicker way to add entries to the front-end logfile.
     *
     * @param string $IPAddr The IP address triggering the log event.
     * @param string $User The user triggering the log event.
     * @param string $Message The message to be logged.
     */
    private function frontendLogger(string $IPAddr, string $User, string $Message)
    {
        /** Guard. */
        if (
            !$this->Loader->Configuration['frontend']['frontend_log'] ||
            !($File = $this->Loader->buildPath($this->Loader->Configuration['frontend']['frontend_log']))
        ) {
            return;
        }

        $Data = $this->Loader->Configuration['legal']['pseudonymise_ip_addresses'] ? $this->Loader->pseudonymiseIP($IPAddr) : $IPAddr;
        $Data .= ' - ' . $this->Loader->timeFormat($this->Loader->Time, $this->Loader->Configuration['core']['time_format']) . ' - "' . $User . '" - ' . $Message . "\n";

        $WriteMode = (!file_exists($File) || (
            $this->Loader->Configuration['core']['truncate'] > 0 &&
            filesize($File) >= $this->Loader->readBytes($this->Loader->Configuration['core']['truncate'])
        )) ? 'wb' : 'ab';

        $Handle = fopen($File, $WriteMode);
        fwrite($Handle, $Data);
        fclose($Handle);
        $this->Loader->logRotation($this->Loader->Configuration['frontend']['frontend_log']);
    }

    /**
     * Wrapper for PHPMailer functionality.
     *
     * @param array $Recipients An array of recipients to send to.
     * @param string $Subject The subject line of the email.
     * @param string $Body The HTML content of the email.
     * @param string $AltBody The alternative plain-text content of the email.
     * @param array $Attachments An optional array of attachments.
     * @return bool Operation failed (false) or succeeded (true).
     */
    private function sendEmail(array $Recipients = [], string $Subject = '', string $Body = '', string $AltBody = '', array $Attachments = []): bool
    {
    }

    /**
     * Generates very simple 8-digit numbers used for 2FA.
     *
     * @return int An 8-digit number.
     */
    private function twoFactorNumber(): int
    {
        if (function_exists('random_int')) {
            try {
                $Key = random_int($this->TwoFactorMinInt, $this->TwoFactorMaxInt);
            } catch (\Exception $e) {
                $Key = rand($this->TwoFactorMinInt, $this->TwoFactorMaxInt);
            }
        }
        return isset($Key) ? $Key : rand($this->TwoFactorMinInt, $this->TwoFactorMaxInt);
    }

    /**
     * Generate a clickable list from an array.
     *
     * @param array $Arr The array to convert from.
     * @param string $DeleteKey The key to use for async calls to delete a cache entry.
     * @param int $Depth Current cache entry list depth.
     * @param string $ParentKey An optional key of the parent data source.
     * @return string The generated clickable list.
     */
    private function arrayToClickableList(array $Arr = [], string $DeleteKey = '', int $Depth = 0, string $ParentKey = ''): string
    {
        $Output = '';
        $Count = count($Arr);
        $Prefix = substr($DeleteKey, 0, 2) === 'fe' ? 'FE' : '';
        foreach ($Arr as $Key => $Value) {
            $Delete = ($Depth === 0) ? ' – (<span style="cursor:pointer" onclick="javascript:' . $DeleteKey . '(\'' . addslashes($Key) . '\')"><code class="s">' . $this->Loader->L10N->getString('field_delete_file') . '</code></span>)' : '';
            $Output .= ($Depth === 0 ? '<span id="' . $Key . $Prefix . 'Container">' : '') . '<li>';
            if (!is_array($Value)) {
                if (substr($Value, 0, 2) === '{"' && substr($Value, -2) === '"}') {
                    $Try = json_decode($Value, true);
                    if ($Try !== null) {
                        $Value = $Try;
                    }
                } elseif (
                    preg_match('~\.ya?ml$~i', $Key) ||
                    (preg_match('~^(?:Data|\d+)$~', $Key) && preg_match('~\.ya?ml$~i', $ParentKey)) ||
                    substr($Value, 0, 4) === "---\n"
                ) {
                    $Try = new \Maikuolan\Common\YAML();
                    if ($Try->process($Value, $Try->Data) && !empty($Try->Data)) {
                        $Value = $Try->Data;
                    }
                } elseif (substr($Value, 0, 2) === '["' && substr($Value, -2) === '"]' && strpos($Value, '","') !== false) {
                    $Value = explode('","', substr($Value, 2, -2));
                }
            }
            if (is_array($Value)) {
                if ($Depth === 0) {
                    $SizeField = $this->Loader->L10N->getString('field_size') ?: 'Size';
                    $Size = isset($Value['Data']) && is_string($Value['Data']) ? strlen($Value['Data']) : (
                        isset($Value[0]) && is_string($Value[0]) ? strlen($Value[0]) : false
                    );
                    if ($Size !== false) {
                        $this->formatFilesize($Size);
                        $Value[$SizeField] = $Size;
                    }
                }
                $Output .= '<span class="comCat" style="cursor:pointer"><code class="s">' . str_replace(['<', '>'], ['&lt;', '&gt;'], $Key) . '</code></span>' . $Delete . '<ul class="comSub">';
                $Output .= $this->arrayToClickableList($Value, $DeleteKey, $Depth + 1, $Key);
                $Output .= '</ul>';
            } else {
                if ($Key === 'Time' && preg_match('~^\d+$~', $Value)) {
                    $Key = $this->Loader->L10N->getString('label_expires');
                    $Value = $this->Loader->timeFormat($Value, $this->Loader->Configuration['core']['time_format']);
                }
                $Class = ($Key === $this->Loader->L10N->getString('field_size') || $Key === $this->Loader->L10N->getString('label_expires')) ? 'txtRd' : 's';
                $Text = ($Count === 1 && $Key === 0) ? $Value : $Key . ($Class === 's' ? ' => ' : '') . $Value;
                $Output .= '<code class="' . $Class . '" style="word-wrap:break-word;word-break:break-all">' . str_replace(['<', '>'], ['&lt;', '&gt;'], $Text) . '</code>' . $Delete;
            }
            $Output .= '</li>' . ($Depth === 0 ? '<br /></span>' : '');
        }
        return $Output;
    }

    /**
     * Attempt to perform some simple formatting for the log data.
     *
     * @param string $In The log data to be formatted.
     */
    private function formatter(string &$In)
    {
        if (strpos($In, "<br />\n") === false) {
            $In = '<div class="fW">' . $In . '</div>';
            return;
        }
        if (strpos($In, "<br />\n<br />\n") !== false) {
            $Data = array_filter(explode("<br />\n<br />\n", $In));
            $SeparatorType = 0;
        } elseif (strpos($In, "\n&gt;") !== false) {
            $Data = preg_split("~(<br />\n(?!-|&gt;)[^\n]+)\n(?!-|&gt;)~i", $In, -1, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
            $SeparatorType = 1;
        } else {
            $Data = array_filter(explode("<br />\n", $In));
            $SeparatorType = 2;
        }
        $In = '';
        if ($SeparatorType === 1) {
            $Blocks = count($Data);
            for ($Block = 0; $Block < $Blocks; $Block += 2) {
                $Darken = empty($Darken);
                $In .= '<div class="h' . ($Darken ? 'B' : 'W') . ' hFd fW">' . $Data[$Block] . $Data[$Block + 1] . "\n</div>";
            }
            $In = '<div style="filter:saturate(60%)"><span class="s">' . $In . '</span></div>';
            return;
        }
        foreach ($Data as &$Block) {
            $Darken = empty($Darken);
            $Block = '<div class="h' . ($Darken ? 'B' : 'W') . ' hFd fW">' . $Block;
            $Block .= $SeparatorType === 0 ? "<br />\n<br />\n</div>" : "<br />\n</div>";
            if ($SeparatorType === 2) {
                $Block = preg_replace([
                    '~(a\:\d+\:)\{~',
                    '~("|\d);\}~',
                    '~\:(\d+)~',
                    '~\:"([^"]+)"~'
                ], [
                    '\1<span class="txtRd">{</span>',
                    '\1;<span class="txtRd">}</span>',
                    ':<span class="txtGn">\1</span>',
                    ':"<span class="txtBl">\1</span>"'
                ], $Block);
            }
        }
        $In = '<div style="filter:saturate(60%)"><span class="' . (
            $SeparatorType === 2 ? 'txtOe' : 's'
        ) . '">' . implode('', $Data) . '</span></div>';
    }

    /**
     * Provides stronger support for LTR inside RTL text.
     *
     * @param string $String The string to work with.
     * @return string The string, modified if necessary.
     */
    private function ltrInRtf(string $String = ''): string
    {
        /** Get direction. */
        $Direction = (
            !isset($this->Loader->L10N) ||
            empty($this->Loader->L10N->Data['Text Direction']) ||
            $this->Loader->L10N->Data['Text Direction'] !== 'rtl'
        ) ? 'ltr' : 'rtl';

        /** If the page isn't RTL, the string should be returned verbatim. */
        if ($Direction !== 'rtl') {
            return $String;
        }

        /** Modify the string to better suit RTL directionality and return it. */
        return preg_replace(
            ['~^(.+)-&gt;(.+)$~i', '~^(.+)➡(.+)$~i'],
            ['\2&lt;-\1', '\2⬅\1'],
            $String
        );
    }

    /**
     * Used to generate new salts when necessary, which may be occasionally used by
     * some specific optional peripheral features (note: should not be considered
     * cryptographically secure; especially so for versions of PHP < 7).
     *
     * @return string Salt.
     */
    private function generateSalt(): string
    {
        $Salt = '';
        if (function_exists('random_int')) {
            try {
                $Length = random_int($this->SaltMinLen, $this->SaltMaxLen);
            } catch (\Exception $e) {
                $Length = rand($this->SaltMinLen, $this->SaltMaxLen);
            }
        } else {
            $Length = rand($this->SaltMinLen, $this->SaltMaxLen);
        }
        if (function_exists('random_bytes')) {
            try {
                $Salt = random_bytes($Length);
            } catch (\Exception $e) {
                $Salt = '';
            }
        }
        if (empty($Salt)) {
            if (function_exists('random_int')) {
                try {
                    for ($Index = 0; $Index < $Length; $Index++) {
                        $Salt .= chr(random_int($this->SaltMinChr, $this->SaltMaxChr));
                    }
                } catch (\Exception $e) {
                    $Salt = '';
                    for ($Index = 0; $Index < $Length; $Index++) {
                        $Salt .= chr(rand($this->SaltMinChr, $this->SaltMaxChr));
                    }
                }
            } else {
                for ($Index = 0; $Index < $Length; $Index++) {
                    $Salt .= chr(rand($this->SaltMinChr, $this->SaltMaxChr));
                }
            }
        }
        return $Salt;
    }
}
