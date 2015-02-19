<?php
/**
 * Contains EWSType_FindItemResponseMessageType.
 */

use jamesiarmes\PEWS\Type\ResponseMessageType;

/**
 * Represents the status and result of a single FindItem operation request.
 *
 * @package php-ews\Types
 */
class EWSType_FindItemResponseMessageType extends ResponseMessageType
{
    /**
     * Contains the results from a search of a single root folder during a
     * FindItem operation.
     *
     * @since Exchange 2007
     *
     * @var EWSType_FindItemParentType
     */
    public $RootFolder;
}
