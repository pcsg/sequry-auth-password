/**
 * Control for registering a user with the gpmauthpassword plugin
 *
 * @module package/pcsg/gpmauthpassword/bin/controls/ChangeAuth
 * @author www.pcsg.de (Patrick Müller)
 *
 * @require qui/controls/Control
 * @require Locale
 * @require css!package/pcsg/gpmauthpassword/bin/controls/ChangeAuth.css
 *
 * @event onSubmit
 */
define('package/pcsg/gpmauthpassword/bin/controls/ChangeAuth', [

    'qui/controls/Control',
    'Locale',

    'css!package/pcsg/gpmauthpassword/bin/controls/ChangeAuth.css'

], function (QUIControl, QUILocale) {
    "use strict";

    var lg = 'pcsg/gpmauthpassword';

    return new Class({

        Extends: QUIControl,
        Type   : 'package/pcsg/gpmauthpassword/bin/controls/ChangeAuth',

        Binds: [
            '$onInject',
            'getOldAuthData',
            'getNewAuthData',
            'submit'
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
                QUILocale.get(lg, 'changeauth.password.label.original') +
                '</span>' +
                '<input type="password" class="gpm-auth-password-input-original"/>' +
                '</label>' +
                '<label>' +
                '<span class="gpm-auth-password-title">' +
                QUILocale.get(lg, 'changeauth.password.label.new') +
                '</span>' +
                '<input type="password" class="gpm-auth-password-input-new"/>' +
                '</label>' +
                '<label>' +
                '<span class="gpm-auth-password-title">' +
                QUILocale.get(lg, 'changeauth.password.label.repeat') +
                '</span>' +
                '<input type="password" class="gpm-auth-password-input-repeat"/>' +
                '</label>'
            );

            return this.$Elm;
        },

        /**
         * event : on inject
         */
        $onInject: function () {
            var self            = this;
            this.$InputOriginal = this.$Elm.getElement('.gpm-auth-password-input-original');
            this.$InputNew      = this.$Elm.getElement('.gpm-auth-password-input-new');
            this.$InputRepeat   = this.$Elm.getElement('.gpm-auth-password-input-repeat');

            this.$InputOriginal.addEvents({
                keydown: function (event) {
                    if (typeof event !== 'undefined' &&
                        event.code === 13) {
                        self.submit();
                    }
                }
            });

            this.$InputNew.addEvents({
                keydown: function (event) {
                    if (typeof event !== 'undefined' &&
                        event.code === 13) {
                        self.submit();
                    }
                }
            });


            this.$InputRepeat.addEvents({
                keydown: function (event) {
                    if (typeof event !== 'undefined' &&
                        event.code === 13) {
                        self.submit();
                    }
                }
            });

            this.$InputOriginal.focus();
        },

        /**
         * Submit data
         */
        submit: function () {
            this.fireEvent('submit');
        },

        /**
         * Checks if all necessary form fields are filled
         *
         * @return {boolean}
         */
        check: function() {
            if (this.$InputOriginal.value.trim() === '' ||
                this.$InputNew.value.trim() === '' ||
                this.$InputRepeat.value.trim() === '') {
                QUI.getMessageHandler(function (MH) {
                    MH.addAttention(
                        QUILocale.get(lg, 'changeauth.fill.inputs')
                    );
                });

                return false;
            }

            if (this.$InputNew.value !== this.$InputRepeat.value) {
                QUI.getMessageHandler(function (MH) {
                    MH.addAttention(
                        QUILocale.get(lg, 'changeauth.password.mismatch')
                    );
                });

                return false;
            }

            return true;
        },

        /**
         * Return old authentication information
         *
         * @return {string}
         */
        getOldAuthData: function () {
            return this.$InputOriginal.value;
        },

        /**
         * Return new authentication information
         *
         * @return {string}
         */
        getNewAuthData: function () {
            return this.$InputNew.value;
        }
    });
});
