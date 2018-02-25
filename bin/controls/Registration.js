/**
 * Control for creating a new password
 *
 * @module package/sequry/auth-password/bin/controls/Registration
 * @author www.pcsg.de (Patrick Müller)
 *
 * @require qui/controls/Control
 * @require Locale
 * @require css!package/sequry/auth-password/bin/controls/Registration.css
 *
 * @event onSubmit
 */
define('package/sequry/auth-password/bin/controls/Registration', [

    'qui/controls/Control',
    'Locale',

    'css!package/sequry/auth-password/bin/controls/Registration.css'

], function (QUIControl, QUILocale) {
    "use strict";

    var lg = 'sequry/auth-password';

    return new Class({

        Extends: QUIControl,
        Type   : 'package/sequry/auth-password/bin/controls/Registration',

        Binds: [
            '$onInject',
            'getAuthData'
        ],

        initialize: function (options) {
            this.parent(options);

            this.$Categories = null;

            this.addEvents({
                onInject: this.$onInject
            });
        },

        /**
         * create the domnode element
         *
         * @return {HTMLDivElement}
         */
        create: function () {
            this.$Elm = this.parent();

            this.$Elm.set(
                'html',
                '<label>' +
                '<span class="gpm-auth-password-title">' +
                QUILocale.get(lg, 'authentication.password.label') +
                '</span>' +
                '<input type="password" class="gpm-auth-password-input"/>' +
                '</label>'
            );

            return this.$Elm;
        },

        /**
         * event : on inject
         */
        $onInject: function () {
            var self  = this;
            var Input = this.$Elm.getElement('.gpm-auth-password-input');

            Input.addEvents({
                keydown: function (event) {
                    if (typeof event !== 'undefined' &&
                        event.code === 13) {
                        self.fireEvent('submit');
                    }
                }
            });

            Input.focus();
        },

        /**
         * Return authentication information
         *
         * @return {string}
         */
        getRegistrationData: function () {
            return this.$Elm.getElement('.gpm-auth-password-input').value;
        }
    });
});
