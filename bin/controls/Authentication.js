/**
 * Control for creating a new password
 *
 * @module package/pcsg/gpmauthpassword/bin/controls/Authentication
 * @author www.pcsg.de (Patrick Müller)
 *
 * @require qui/controls/Control
 * @require Locale
 * @require css!package/pcsg/gpmauthpassword/bin/controls/Authentication.css
 *
 * @event onSubmit
 */
define('package/pcsg/gpmauthpassword/bin/controls/Authentication', [

    'qui/controls/Control',
    'Locale',

    'css!package/pcsg/gpmauthpassword/bin/controls/Authentication.css'

], function (QUIControl, QUILocale) {
    "use strict";

    var lg = 'pcsg/gpmauthpassword';

    return new Class({

        Extends: QUIControl,
        Type   : 'package/pcsg/gpmauthpassword/bin/controls/Authentication',

        Binds: [
            '$onInject',
            'getAuthData'
        ],

        initialize: function (options) {
            this.parent(options);

            this.$Categories = null;
            this.$Input      = null;

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
            var self = this;

            this.$Input = this.$Elm.getElement('.gpm-auth-password-input');

            this.$Input.addEvents({
                keydown: function (event) {
                    if (typeof event !== 'undefined' &&
                        event.code === 13) {
                        self.fireEvent('submit');
                    }
                }
            });
        },

        focus: function () {
            this.$Input.focus();
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
