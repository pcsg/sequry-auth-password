<?php

/**
 * This file contains \QUI\Kapitalschutz\Events
 */

namespace Pcsg\GpmAuthPassword;

use Pcsg\GroupPasswordManager\Actors\CryptoUser;
use Pcsg\GroupPasswordManager\Security\KDF;
use Pcsg\GroupPasswordManager\Security\Keys\Key;
use Pcsg\GroupPasswordManager\Security\Random;
use QUI;
use Pcsg\GroupPasswordManager\Security\Interfaces\IAuthPlugin;
use Pcsg\GroupPasswordManager\Security\Handler\Authentication;
use QUI\Users\Auth\QUIQQER as QUIAuth;
use Pcsg\GroupPasswordManager\Security\HiddenString;

/**
 * Class Events
 *
 * @package pcsg/gpmauthpassword
 * @author www.pcsg.de (Patrick Müller)
 */
class AuthPlugin implements IAuthPlugin
{
    const NAME = 'QUIQQER Login-Passwort';
    const TBL  = 'pcsg_gpm_auth_password';

    /**
     * Flag for user password change
     *
     * @var bool
     */
    public static $passwordChange = false;

    /**
     * Flag: If this flag is set to true, a call of changeAuthenticationInformation()
     * will also change the quiqqer user password.
     *
     * @var bool [default: false]
     */
    public static $changePasswordEvent = false;

    /**
     * The authentication information for different users
     *
     * @var HiddenString[]
     */
    protected static $authInformation = array();

    /**
     * Return locale data for auth plugin name
     *
     * @return array
     */
    public static function getNameLocaleData()
    {
        return array(
            'pcsg/gpmauthpassword',
            'plugin.name'
        );
    }

    /**
     * Return locale data for auth plugin description
     *
     * @return array
     */
    public static function getDescriptionLocaleData()
    {
        return array(
            'pcsg/gpmauthpassword',
            'plugin.description'
        );
    }

    /**
     * Authenticate a user with this plugin
     *
     * @param HiddenString $information
     * @param \QUI\Users\User $User (optional) - if omitted, use current session user
     * @return true - if authenticated
     * @throws QUI\Exception
     */
    public static function authenticate(HiddenString $information, $User = null)
    {
        if (self::$changePasswordEvent) {
            self::$authInformation[$User->getId()] = $information;
            return true;
        }

        if (is_null($User)) {
            $User = QUI::getUserBySession();
        }

        if (self::isAuthenticated($User)) {
            return true;
        }

        if (!self::isRegistered($User)) {
            // @todo eigenen 401 error code
            throw new QUI\Exception(array(
                'pcsg/gpmauthpassword',
                'exception.user.not.registered'
            ));
        }

        if (!self::checkQuiqqerPassword($User, $information)) {
            // @todo eigenen 401 error code
            throw new QUI\Exception(array(
                'pcsg/gpmauthpassword',
                'exception.user.authentication.data.wrong'
            ));
        }

        self::$authInformation[$User->getId()] = $information;

        return true;
    }

    /**
     * Checks if a user is successfully authenticated for this runtime
     *
     * @param \QUI\Users\User $User (optional) - if omitted, use current session user
     * @return bool
     */
    public static function isAuthenticated($User = null)
    {
        if (is_null($User)) {
            $User = QUI::getUserBySession();
        }

        return isset(self::$authInformation[$User->getId()]);
    }

    /**
     * Get the derived key from the authentication information of a specific user
     *
     * @param \QUI\Users\User $User (optional) - if omitted, use current session user
     * @return Key
     * @throws QUI\Exception
     */
    public static function getDerivedKey($User = null)
    {
        if (is_null($User)) {
            $User = QUI::getUserBySession();
        }

        if (!self::isAuthenticated($User)) {
            throw new QUI\Exception(array(
                'pcsg/gpmauthpassword',
                'exception.derive.key.user.not.authenticated'
            ));
        }

        return KDF::createKey(
            self::$authInformation[$User->getId()],
            self::getSalt($User)
        );
    }

    /**
     * Returns URL QUI\Control that collects authentification information
     *
     * @return string - \QUI\Control URL
     */
    public static function getAuthenticationControl()
    {
        return 'package/pcsg/gpmauthpassword/bin/controls/Authentication';
    }

    /**
     * Change authentication information
     *
     * @param HiddenString $old - current authentication information
     * @param HiddenString $new - new authentication information
     * @param \QUI\Users\User $User (optional) - if omitted, use current session user
     *
     * @return void
     * @throws QUI\Exception
     */
    public static function changeAuthenticationInformation(HiddenString $old, HiddenString $new, $User = null)
    {
        if (is_null($User)) {
            $User = QUI::getUserBySession();
        }

        if (!self::isRegistered($User)) {
            throw new QUI\Exception(array(
                'pcsg/gpmauthpassword',
                'exception.change.auth.user.not.registered'
            ));
        }

        if (self::$changePasswordEvent) {
            self::$authInformation[$User->getId()] = $new;
            return;
        }

        // check old authentication information
        if (!self::checkQuiqqerPassword($User, $old)) {
            throw new QUI\Exception(array(
                'pcsg/gpmauthpassword',
                'exception.change.auth.old.information.wrong'
            ));
        }

        // check new authentication information
        $new = trim($new);

        if (empty($new)) {
            throw new QUI\Exception(array(
                'pcsg/gpmauthpassword',
                'exception.change.auth.new.information.empty'
            ));
        }

        // set new user password
        self::$passwordChange = true;
        $User->setPassword($new);
        self::$passwordChange = false;

        self::$authInformation[$User->getId()] = $new;
    }

    /**
     * Get the salt used for key derivation
     *
     * @param \QUI\Users\User $User (optional) - if omitted, use current session user
     * @return string
     */
    protected static function getSalt($User = null)
    {
        if (is_null($User)) {
            $User = QUI::getUserBySession();
        }

        $result = QUI::getDataBase()->fetch(array(
            'select' => array('salt'),
            'from'   => self::TBL,
            'where'  => array(
                'userId' => $User->getId()
            )
        ));

        // @todo ggf. abfragen ob existent
        $salt = $result[0]['salt'];

        return $salt;
    }

    /**
     * Registers a user with this plugin
     *
     * @param HiddenString $information - registration information given by the user
     * @param \QUI\Users\User $User (optional) - if omitted, use current session user
     * @return HiddenString - authentication information
     *
     * @throws QUI\Exception
     */
    public static function register(HiddenString $information, $User = null)
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

        if (!self::checkQuiqqerPassword($User, $information)) {
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

        return $information;
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
     * Returns URL of QUI\Control that collects registration information
     *
     * @return string - \QUI\Control URL
     */
    public static function getRegistrationControl()
    {
        return 'package/pcsg/gpmauthpassword/bin/controls/Registration';
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
            'Authentifizierung mit dem QUIQQER Login-Passwort'
        );
    }

    /**
     * Returns URL of QUI\Control that allows changing of authentication information
     *
     * @return string - \QUI\Control URL
     */
    public static function getChangeAuthenticationControl()
    {
        return 'package/pcsg/gpmauthpassword/bin/controls/ChangeAuth';
    }

    /**
     * Delete a user from this plugin
     *
     * @param CryptoUser $CryptoUser
     * @return mixed
     */
    public static function deleteUser($CryptoUser)
    {
        QUI::getDataBase()->delete(
            self::TBL,
            array(
                'userId' => $CryptoUser->getId()
            )
        );
    }

    /**
     * Checks if a quiqqer login password is correct
     *
     * @param QUI\Users\User $User
     * @param HiddenString $password - login password
     *
     * @return bool
     */
    protected static function checkQuiqqerPassword($User, HiddenString $password)
    {
        $QUIAuth = new QUIAuth($User->getUsername());

        try {
            $QUIAuth->auth($password->getString());
        } catch (\Exception $Exception) {
            return false;
        }

        return true;
    }
}
