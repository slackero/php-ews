<?php
/**
 * Contains EWSType_ExportItemsResponseMessageType.
 */

use jamesiarmes\PEWS\Type\ResponseMessageType;

/**
 * Represents the status and results of a request to export a single mailbox
 * item.
 *
 * @package php-ews\Types
 */
class EWSType_ExportItemsResponseMessageType extends ResponseMessageType
{
    /**
     * Contains the contents of an exported item.
     *
     * @since Exchange 2010 SP1
     *
     * @var string
     *
     * @todo Create a base64 class?
     */
    public $Data;
}
