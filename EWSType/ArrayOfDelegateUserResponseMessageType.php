<?php
/**
 * Contains EWSType_ArrayOfDelegateUserResponseMessageType.
 */

use jamesiarmes\PEWS\Type\BaseDelegateResponseMessageType;

/**
 * Contains the response messages for an Exchange Web Services delegate
 * management request.
 *
 * @package php-ews\Types
 */
class EWSType_ArrayOfDelegateUserResponseMessageType extends
    BaseDelegateResponseMessageType
{
    /**
     * Contains response messages for delegate management operations.
     *
     * @since Exchange 2007 SP1
     *
     * @var EWSType_DelegateUserResponseMessageType
     */
    public $DelegateUserResponseMessageType;
}
