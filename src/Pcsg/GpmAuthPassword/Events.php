<?php

/**
 * This file contains \Pcsg\GpmAuthPassword\Events
 */

namespace Pcsg\GpmAuthPassword;

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
     * on event : onPackageSetup
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
}