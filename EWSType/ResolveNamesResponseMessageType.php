<?php
/**
 * Contains EWSType_ResolveNamesResponseMessageType.
 */

use jamesiarmes\PEWS\Type\ResponseMessageType;

/**
 * Defines the status and result of a ResolveNames operation request.
 *
 * @package php-ews\Types
 */
class EWSType_ResolveNamesResponseMessageType extends ResponseMessageType
{
    /**
     * Contains an array of resolutions for an ambiguous name.
     *
     * @since Exchange 2007
     *
     * @var EWSType_ArrayOfResolutionType
     */
    public $ResolutionSet;
}
