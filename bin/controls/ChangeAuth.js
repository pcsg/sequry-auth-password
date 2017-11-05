/**
 * Control for collecting authentication data
 *
 * @module package/pcsg/gpmauthpassword/bin/controls/ChangeAuth
 * @author www.pcsg.de (Patrick Müller)
 *
 * @event onSubmit
 */
define('package/pcsg/gpmauthpassword/bin/controls/ChangeAuth', [

    'package/pcsg/grouppasswordmanager/bin/controls/authPlugins/ChangeAuth',

    'Locale',
    'Mustache',

    'text!package/pcsg/gpmauthpassword/bin/controls/ChangeAuth.html',
    'css!package/pcsg/gpmauthpassword/bin/controls/ChangeAuth.css'

], function (ChangeAuthBaseClass, QUILocale, Mustache, template) {
    "use strict";

    var lg = 'pcsg/gpmauthpassword';

    return new Class({

        Extends: ChangeAuthBaseClass,
        Type   : 'package/pcsg/gpmauthpassword/bin/controls/ChangeAuth',

        Binds: [
            '$onInject',
            'getOldAuthData',
            'getNewAuthData',
            'submit'
        ],

        initialize: function (options) {
            this.parent(options);

            this.$PasswordInput      = null;
            this.$PasswordCheckInput = null;
            this.$MsgElm             = null;

            this.addEvents({
                onInject: this.$onInject
            });
        },

        /**
         * Event: onImport
         */
        $onImport: function () {
            var self = this;

            this.parent();

            var lgPrefix = 'controls.changeauth.template.';

            var Content = new Element('div', {
                'class': 'pcsg-gpm-auth-password-change',
                html   : Mustache.render(template, {
                    labelPassword     : QUILocale.get(lg, lgPrefix + 'labelPassword'),
                    labelPasswordCheck: QUILocale.get(lg, lgPrefix + 'labelPasswordCheck')
                })
            }).inject(this.$Input, 'after');

            this.$PasswordInput      = Content.getElement('.pcsg-gpm-auth-password-change-input');
            this.$PasswordCheckInput = Content.getElement('.pcsg-gpm-auth-password-change-input-check');

            var OnKeyDown = function (event) {
                if (typeof event !== 'undefined' &&
                    event.code === 13) {
                    self.submit();
                }
            };

            this.$PasswordInput.addEvents({
                keydown: OnKeyDown,
                blur   : this.$check
            });

            this.$PasswordCheckInput.addEvents({
                keydown: OnKeyDown,
                blur   : this.$check
            });

            this.$MsgElm = Content.getElement('.pcsg-gpm-auth-password-change-msg');
        },

        /**
         * Submit data
         */
        submit: function () {
            if (this.$check()) {
                this.fireEvent('submit', [this.getAuthData(), this]);
            }
        },

        /**
         * Check if passwords are equal
         *
         * @returns {boolean}
         */
        $check: function () {
            var pass      = this.$PasswordInput.value.trim();
            var passCheck = this.$PasswordCheckInput.value.trim();

            if (pass === passCheck) {
                return true;
            }

            this.$MsgElm.set(
                'html',
                QUILocale.get(
                    lg,
                    'controls.changeauth.password_mismatch'
                )
            );

            return false;
        },

        /**
         * Focus the element for authentication data input
         */
        focus: function () {
            this.$PasswordInput.focus();
        },

        /**
         * Enable the element for authentication data input
         */
        enable: function () {
            this.$PasswordInput.disabled      = false;
            this.$PasswordCheckInput.disabled = false;
        },

        /**
         * Disable the element for authentication data input
         */
        disable: function () {
            this.$PasswordInput.disabled      = true;
            this.$PasswordCheckInput.disabled = true;
        },

        /**
         * Return authentication information
         *
         * @return {string}
         */
        getAuthData: function () {
            return this.$PasswordInput.value.trim();
        }
    });
});
