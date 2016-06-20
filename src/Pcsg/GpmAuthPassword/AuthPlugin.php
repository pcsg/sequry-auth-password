<?php

/**
 * This file contains \QUI\Kapitalschutz\Events
 */

namespace Pcsg\GpmAuthPassword;

use QUI;
use Pcsg\GroupPasswordManager\Security\Interfaces\iAuthPlugin;
use Pcsg\GroupPasswordManager\Handler\Authentification;

/**
 * Class Events
 *
 * @package kapitalschutz/kanzlei
 * @author www.pcsg.de (Patrick Müller)
 */
class AuthPlugin implements iAuthPlugin
{
    const NAME = 'Password Authentification';

    /**
     * Current Plugin User
     *
     * @var QUI\Users\User
     */
    protected $User = null;

    /**
     * @param \QUI\Users\User $User (optional) - The User this plugin should authenticate; if ommitted User = session user
     */
    public function __construct($User = null)
    {
        if (!is_null($User)) {
            $this->User = $User;
        } else {
            $this->User = QUI::getUserBySession();
        }
    }

    /**
     * Return internal name of auth plugin
     *
     * @return String
     */
    public function getName()
    {
        return $this::NAME;
    }

    /**
     * Authenticate the current user
     *
     * @param mixed $information
     * @return mixed
     */
    public function authenticate($information = null)
    {

    }

    /**
     * Checks if the current user is successfully authenticated for this runtime
     *
     * @return bool
     */
    public function isAuthenticated()
    {
        // @todo
    }

    /**
     * Returns a QUI\Control object that collects information for generating
     * a unique key (i.e. input fields)
     *
     * @return \QUI\Control
     */
    public function getControl()
    {
        // @todo
    }

    /**
     * Registers the auth plugin with the main password manager module
     *
     * @return void
     */
    public static function registerPlugin()
    {
        Authentification::registerPlugin(
            self::class,
            self::NAME
        );
    }
}