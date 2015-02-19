<?php
/**
 * Contains \jamesiarmes\PEWS\Type\ReferenceItemResponseType.
 */

namespace jamesiarmes\PEWS\Type;

/**
 * Base class for responding to items with a reference.
 *
 * ObjectName property is prohibited.
 *
 * @package php-ews\Types
 */
class ReferenceItemResponseType extends ResponseObjectType
{
    /**
     * {@inheritdoc}
     *
     * @prohibited
     */
    public $ObjectName;
}
