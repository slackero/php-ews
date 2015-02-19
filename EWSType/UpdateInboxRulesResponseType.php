<?php
/**
 * Contains EWSType_UpdateInboxRulesResponseType.
 */

use jamesiarmes\PEWS\Type\ResponseMessageType;

/**
 * Defines a response to an UpdateInboxRules request.
 *
 * @package php-ews\Types
 */
class EWSType_UpdateInboxRulesResponseType extends ResponseMessageType
{
    /**
     * Represents an array of rule validation errors on each rule field that has
     * an error.
     *
     * @since Exchange 2010
     *
     * @var EWSType_ArrayOfRuleOperationErrorsType
     */
    public $RuleOperationErrors;
}
