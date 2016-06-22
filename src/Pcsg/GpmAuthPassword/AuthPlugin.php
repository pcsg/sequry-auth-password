<?php

/**
 * This file contains \QUI\Kapitalschutz\Events
 */

namespace Pcsg\GpmAuthPassword;

use Pcsg\GroupPasswordManager\Security\KDF;
use Pcsg\GroupPasswordManager\Security\Keys\Key;
use Pcsg\GroupPasswordManager\Security\Random;
use QUI;
use Pcsg\GroupPasswordManager\Security\Interfaces\iAuthPlugin;
use Pcsg\GroupPasswordManager\Security\Handler\Authentication;
use QUI\Users\Auth as QUIAuth;

/**
 * Class Events
 *
 * @package pcsg/gpmauthpassword
 * @author www.pcsg.de (Patrick Müller)
 */
class AuthPlugin implements iAuthPlugin
{
    const NAME = 'Password Authentification';
    const TBL  = 'pcsg_gpm_auth_password';

    /**
     * Current Plugin User
     *
     * @var QUI\Users\User
     */
    protected $User = null;

    /**
     * The authentication information
     *
     * @var string
     */
    protected $authInformation = null;

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
     * @return true - if authenticated
     * @throws QUI\Exception
     */
    public function authenticate($information = null)
    {
        if (!self::isRegistered($this->User)) {
            throw new QUI\Exception(array(
                'pcsg/gpmauthpassword',
                'exception.user.not.registered'
            ), 401);
        }

        $QUIAuth = new QUIAuth($this->User->getUsername());
        $auth    = $QUIAuth->auth($information);

        if (!$auth) {
            throw new QUI\Exception(array(
                'pcsg/gpmauthpassword',
                'exception.user.authentication.data.wrong'
            ), 401);
        }

        $this->authInformation = $information;

        return true;
    }

    /**
     * Checks if the current user is successfully authenticated for this runtime
     *
     * @return bool
     */
    public function isAuthenticated()
    {
        return !is_null($this->authInformation);
    }

    /**
     * Get the derived key from the authentication information
     *
     * @return Key
     * @throws QUI\Exception
     */
    public function getDerivedKey()
    {
        if (!$this->isAuthenticated()) {
            throw new QUI\Exception(array(
                'pcsg/gpmauthpassword',
                'exception.derive.key.user.not.authenticated'
            ));
        }

        return KDF::createKey($this->authInformation, $this->getSalt());
    }

    /**
     * Returns a QUI\Control object that collects authentification information
     *
     * @return \QUI\Control
     */
    public function getAuthenticationControl()
    {
        return 'package/pcsg/gpmauthpassword/bin/controls/Authentication';
    }

    /**
     * Get the salt used for key derivation
     *
     * @return string
     */
    protected function getSalt()
    {
        $result = QUI::getDataBase()->fetch(array(
            'select' => array('salt'),
            'from'   => self::TBL,
            'where'  => array(
                'userId' => $this->User->getId()
            )
        ));

        // @todo ggf. abfragen ob existent
        $salt = $result[0]['salt'];

        return $salt;
    }

    /**
     * Registers the current user and creates a new keypair
     *
     * @param \QUI\Users\User $User (optional) - if omitted, use current session user
     * @param mixed $information - authentication information given by the user
     * @return bool - success
     * @throws QUI\Exception
     */
    public static function register($User = null, $information = null)
    {
        if (is_null($User)) {
            $User = QUI::getUserBySession();
        }

        if (self::isRegistered($User)) {
            throw new QUI\Exception(array(
                'pcsg/gpmauthpassword',
                'exception.user.already.registered'
            ));
        }

        $QUIAuth = new QUIAuth($User->getUsername());
        $auth    = $QUIAuth->auth($information);

        if (!$auth) {
            throw new QUI\Exception(array(
                'pcsg/gpmauthpassword',
                'exception.registration.with.quiqqer.password.only'
            ));
        }

        $randSalt = Random::getRandomData();

        QUI::getDataBase()->insert(
            self::TBL,
            array(
                'userId' => $User->getId(),
                'salt'   => $randSalt
            )
        );
    }

    /**
     * Checks if a user is successfully registered with this auth plugin
     *
     * @param QUI\Users\User $User (optional) - if ommitted, use current session user
     * @return bool
     */
    public static function isRegistered($User = null)
    {
        if (is_null($User)) {
            $User = QUI::getUserBySession();
        }

        $result = QUI::getDataBase()->fetch(array(
            'count' => 1,
            'from'  => self::TBL,
            'where' => array(
                'userId' => $User->getId()
            )
        ));

        if (current(current($result)) == 0) {
            return false;
        }

        return true;
    }

    /**
     * Get list of User IDs of users that are registered with this plugin
     *
     * @return array
     */
    public static function getRegisteredUserIds()
    {
        $userIds = array();

        $result = QUI::getDataBase()->fetch(array(
            'select' => array(
                'userId'
            ),
            'from'  => self::TBL
        ));

        foreach ($result as $row) {
            $userIds[] = $row['userId'];
        }

        return $userIds;
    }

    /**
     * Registers the auth plugin with the main password manager module
     *
     * @return void
     */
    public static function registerPlugin()
    {
        Authentication::registerPlugin(
            self::class,
            self::NAME,
            'Password authentication via QUIQQER Login password'
        );
    }
}