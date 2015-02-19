<?php
/**
 * Contains EWSType_ServiceConfigurationResponseMessageType.
 */

use jamesiarmes\PEWS\Type\ResponseMessageType;

/**
 * Represents service configuration settings.
 *
 * @package php-ews\Types
 */
class EWSType_ServiceConfigurationResponseMessageType extends
    ResponseMessageType
{
    /**
     * Contains service configuration information for the mail tips service.
     *
     * @since Exchange 2010
     *
     * @var EWSType_MailTipsServiceConfiguration
     */
    public $MailTipsConfiguration;

    /**
     * Contains service configuration information for the protection rules
     * service.
     *
     * @since Exchange 2010
     *
     * @var EWSType_ProtectionRulesServiceConfiguration
     */
    public $ProtectionRulesConfiguration;

    /**
     * Contains service configuration information for the Unified Messaging
     * service.
     *
     * @since Exchange 2010
     *
     * @var EWSType_UnifiedMessageServiceConfiguration
     */
    public $UnifiedMessagingConfiguration;
}
