<?php

namespace Sequry\Auth\Password;

use Sequry\Core\Constants\Tables;
use Sequry\Core\Security\Handler\Authentication;
use Sequry\Core\Security\Handler\Recovery;
use Sequry\Core\Security\HiddenString;
use QUI;

/**
 * Class Events
 *
 * @package sequry/auth-password
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
                'sequry/auth-password',
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

            $newPass = new HiddenString($newPass);

            $AuthPlugin = Authentication::getAuthPlugin($result[0]['id']);
            $AuthPlugin->changeAuthenticationInformation(
                new HiddenString($oldPass),
                $newPass,
                $User
            );
        } catch (\Exception $Exception) {
            QUI\System\Log::addError(
                'onUserChangePassword :: Could not change password for User #' . $User->getId()
                . ' -> ' . $Exception->getMessage()
            );

            throw new QUI\Exception(array(
                'sequry/auth-password',
                'exception.event.userchangepassword',
                array(
                    'userName' => $User->getUsername(),
                    'userId'   => $User->getId()
                )
            ));
        }

        QUI::getAjax()->triggerGlobalJavaScriptCallback(
            'showRecoveryCode',
            array(
                'recoveryCode' => Recovery::createEntry($AuthPlugin, $newPass)
            )
        );

        QUI::getMessagesHandler()->addAttention(
            QUI::getLocale()->get(
                'sequry/auth-password',
                'attention.event.userchangepassword',
                array(
                    'userName' => $User->getUsername(),
                    'userId'   => $User->getId()
                )
            )
        );
    }
}
