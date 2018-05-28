/**
 * Control for creating a new password
 *
 * @module package/sequry/auth-password/bin/controls/Registration
 * @author www.pcsg.de (Patrick Müller)
 *
 * @event onSubmit
 */
define('package/sequry/auth-password/bin/controls/Registration', [

    'package/sequry/core/bin/controls/authPlugins/Registration',

    'Locale',
    'Mustache',

    'text!package/sequry/auth-password/bin/controls/Registration.html',
    'css!package/sequry/auth-password/bin/controls/Registration.css'

], function (RegistrationBaseClass, QUILocale, Mustache, template) {
    "use strict";

    var lg = 'sequry/auth-password';

    return new Class({

        Extends: RegistrationBaseClass,
        Type   : 'package/sequry/auth-password/bin/controls/Registration',

        Binds: [
            '$onInject',
            'getAuthData'
        ],

        initialize: function (options) {
            this.parent(options);

            this.$PasswordInput = null;

            this.addEvents({
                onInject: this.$onInject
            });
        },

        /**
         * event : on inject
         */
        $onInject: function () {
            var self     = this;
            var lgPrefix = 'controls.Registration.template.';

            var Content = new Element('div', {
                'class': 'sequry-auth-password-registration',
                html   : Mustache.render(template, {
                    labelPassword: QUILocale.get(lg, lgPrefix + 'labelPassword')
                })
            }).inject(this.$Elm);

            this.$PasswordInput = Content.getElement('input.sequry-auth-password-registration-input');

            this.$PasswordInput.addEvents({
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
            this.$PasswordInput.focus();
        },

        /**
         * Return authentication information
         *
         * @return {string}
         */
        getAuthData: function () {
            return this.$PasswordInput.value;
        }
    });
});
