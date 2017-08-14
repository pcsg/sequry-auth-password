/**
 * Authentication control for pcsg/gpmauthpassword
 *
 * @module package/pcsg/gpmauthpassword/bin/controls/Authentication
 * @author www.pcsg.de (Patrick Müller)
 *
 * @require package/pcsg/grouppasswordmanager/bin/controls/authPlugins/Authentication
 * @require Locale
 * @require css!package/pcsg/gpmauthpassword/bin/controls/Authentication.css
 *
 * @event onSubmit
 */
define('package/pcsg/gpmauthpassword/bin/controls/Authentication', [

    'package/pcsg/grouppasswordmanager/bin/controls/authPlugins/Authentication',
    'Locale',

    'css!package/pcsg/gpmauthpassword/bin/controls/Authentication.css'

], function (AuthenticationBaseClass, QUILocale) {
    "use strict";

    var lg = 'pcsg/gpmauthpassword';

    return new Class({

        Extends: AuthenticationBaseClass,
        Type   : 'package/pcsg/gpmauthpassword/bin/controls/Authentication',

        Binds: [
            '$onImport',
            'focus',
            'enable',
            'disable',
            'getAuthData'
        ],

        /**
         * Event: onImport
         */
        $onImport: function () {
            var self = this;

            this.parent();

            this.$Input.type        = 'password';
            this.$Input.placeholder = QUILocale.get(lg, 'authentication.password.label');

            this.$Input.addEvents({
                keydown: function (event) {
                    if (typeof event !== 'undefined' &&
                        event.code === 13) {
                        self.fireEvent('submit');
                    }
                }
            });
        },

        /**
         * Focus the element for authentication data input
         */
        focus: function () {
            this.$Input.focus();
        },

        /**
         * Enable the element for authentication data input
         */
        enable: function () {
            this.$Input.disabled = false;
        },

        /**
         * Disable the element for authentication data input
         */
        disable: function () {
            this.$Input.disabled = true;
        },

        /**
         * Show the element for authentication data input
         */
        show: function () {
            this.$Input.setStyle('display', '');
        },

        /**
         * Hide the element for authentication data input
         */
        hide: function () {
            this.$Input.setStyle('display', 'none');
        },

        /**
         * Return authentication information
         *
         * @return {string}
         */
        getAuthData: function () {
            return this.$Input.value;
        }
    });
});
