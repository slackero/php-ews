<?php
/**
 * Contains \jamesiarmes\PEWS\Type\ConvertIdResponseMessageType.
 */

namespace jamesiarmes\PEWS\Type;

/**
 * Represents the status and result of a ConvertId operation request.
 *
 * @package php-ews\Types
 */
class ConvertIdResponseMessageType extends ResponseMessageType
{
    /**
     * Describes a converted identifier in the response.
     *
     * @since Exchange 2007 SP1
     *
     * @var \jamesiarmes\PEWS\Type\AlternateIdType
     */
    public $AlternateId;
}
