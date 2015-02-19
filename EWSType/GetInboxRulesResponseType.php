<?php
/**
 * Contains EWSType_GetInboxRulesResponseType.
 */

use jamesiarmes\PEWS\Type\ResponseMessageType;

/**
 * Defines a response to a GetInboxRules operation request.
 *
 * @package php-ews\Types
 */
class EWSType_GetInboxRulesResponseType extends ResponseMessageType
{
    /**
     * Represents an array of the rules in the user's mailbox.
     *
     * @since Exchange 2010
     *
     * @var EWSType_ArrayOfRulesType
     */
    public $InboxRules;

    /**
     * Indicates whether a Microsoft Outlook rule blob exists in the user's
     * mailbox.
     *
     * @since Exchange 2010
     *
     * @var boolean
     */
    public $OutlookRuleBlobExists;
}
