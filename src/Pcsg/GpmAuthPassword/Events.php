<?php

/**
 * This file contains \Pcsg\GpmAuthPassword\Events
 */

namespace Pcsg\GpmAuthPassword;

use Pcsg\GroupPasswordManager\Constants\Tables;
use Pcsg\GroupPasswordManager\Security\Authentication\Plugin;
use Pcsg\GroupPasswordManager\Security\Handler\Authentication;
use QUI;

/**
 * Class Events
 *
 * @package pcsg/gpmauthpassword
 * @author www.pcsg.de (Patrick Müller)
 */
class Events
{
    /**
     * Event on user password change (user password is changes by SuperUser)
     *
     * @param QUI\Users\User $User
     * @throws QUI\Exception
     */
    public static function onUserSetPassword($User)
    {
        if (AuthPlugin::isRegistered($User)
            && !AuthPlugin::$passwordChange
        ) {
            throw new QUI\Exception(array(
                'pcsg/gpmauthpassword',
                'exception.set.password.only.via.plugin',
                array(
                    'userName' => $User->getUsername(),
                    'userId'   => $User->getId()
                )
            ));
        }
    }

    /**
     * Event on user password change (user changes his own password)
     *
     * @param QUI\Users\User $User
     * @param string $newPass
     * @param string $oldPass
     *
     * @throws QUI\Exception
     */
    public static function onUserChangePasswordBefore($User, $newPass, $oldPass)
    {
        if (!AuthPlugin::isRegistered($User)) {
            return;
        }

        // 1. fetch auth plugin id from quiqqer/grouppasswordmanager
        $result = $result = QUI::getDataBase()->fetch(array(
            'select' => array(
                'id'
            ),
            'from'   => Tables::AUTH_PLUGINS,
            'where'  => array(
                'path' => '\\' . AuthPlugin::class
            )
        ));

        if (empty($result)) {
            return;
        }

        try {
            AuthPlugin::$changePasswordEvent = true;

            $AuthPlugin = Authentication::getAuthPlugin($result[0]['id']);
            $AuthPlugin->changeAuthenticationInformation(
                $oldPass,
                $newPass,
                $User
            );
        } catch (\Exception $Exception) {
            QUI\System\Log::addError(
                'onUserChangePassword :: Could not change password for User #' . $User->getId()
                . ' -> ' . $Exception->getMessage()
            );

            throw new QUI\Exception(array(
                'pcsg/gpmauthpassword',
                'exception.event.userchangepassword',
                array(
                    'userName' => $User->getUsername(),
                    'userId'   => $User->getId()
                )
            ));
        }

        QUI::getMessagesHandler()->addAttention(
            QUI::getLocale()->get(
                'pcsg/gpmauthpassword',
                'attention.event.userchangepassword',
                array(
                    'userName' => $User->getUsername(),
                    'userId'   => $User->getId()
                )
            )
        );
    }
}
