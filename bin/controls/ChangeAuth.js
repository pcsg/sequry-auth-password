/**
 * Control for collecting authentication data
 *
 * @module package/sequry/auth-password/bin/controls/ChangeAuth
 * @author www.pcsg.de (Patrick Müller)
 *
 * @event onSubmit [this]
 */
define('package/sequry/auth-password/bin/controls/ChangeAuth', [

    'package/sequry/core/bin/controls/authPlugins/ChangeAuth',

    'Locale',
    'Mustache',

    'text!package/sequry/auth-password/bin/controls/ChangeAuth.html',
    'css!package/sequry/auth-password/bin/controls/ChangeAuth.css'

], function (ChangeAuthBaseClass, QUILocale, Mustache, template) {
    "use strict";

    var lg = 'sequry/auth-password';

    return new Class({

        Extends: ChangeAuthBaseClass,
        Type   : 'package/sequry/auth-password/bin/controls/ChangeAuth',

        Binds: [
            '$onInject',
            'checkNewAuthData',
            'checkOldAuthData',
            'getAuthData',
            'submit',
            'focus',
            'enable',
            'disable'
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
         * Event: onInject
         */
        $onInject: function () {
            var self     = this;
            var lgPrefix = 'controls.changeauth.template.';

            var Content = new Element('div', {
                'class': 'sequry-auth-password-change',
                html   : Mustache.render(template, {
                    labelPassword     : QUILocale.get(lg, lgPrefix + 'labelPassword'),
                    labelPasswordCheck: QUILocale.get(lg, lgPrefix + 'labelPasswordCheck')
                })
            }).inject(this.$Elm);

            this.$PasswordInput      = Content.getElement('.sequry-auth-password-change-input');
            this.$PasswordCheckInput = Content.getElement('.sequry-auth-password-change-input-check');

            var OnKeyDown = function (event) {
                if (typeof event !== 'undefined' &&
                    event.code === 13) {
                    self.fireEvent('submit', [self]);
                }
            };

            this.$PasswordInput.addEvents({
                keydown: OnKeyDown
            });

            this.$PasswordCheckInput.addEvents({
                keydown: OnKeyDown
            });

            this.$MsgElm = Content.getElement('.sequry-auth-password-change-msg');
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
         * Checks if the new authentication information input is correct
         *
         * @return {boolean} - Correctness of information
         */
        checkAuthData: function () {
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

            this.$MsgElm.setStyle('display', 'block');

            return false;
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
