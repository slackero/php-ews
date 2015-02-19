<?php
/**
 * Contains \jamesiarmes\PEWS\Type\ResponseObjectType.
 */

namespace jamesiarmes\PEWS\Type;

/**
 * Base type for reply objects.
 *
 * @package php-ews\Types
 */
abstract class ResponseObjectType extends ResponseObjectCoreType
{
    /**
     * Item identifier that is related to a response object.
     *
     * @since Exchange 2007
     *
     * @var string
     */
    public $ReferenceItemId;
}
