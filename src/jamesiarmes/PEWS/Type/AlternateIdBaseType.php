<?php
/**
 * Contains \jamesiarmes\PEWS\Type\AlternateIdBaseType.
 */

namespace jamesiarmes\PEWS\Type;

use jamesiarmes\PEWS\Type;

/**
 * Base class for alternate id types.
 *
 * @package php-ews\Types
 */
abstract class AlternateIdBaseType extends Type
{
    /**
     * Describes the source or destination format in a request.
     *
     * @since Exchange 2007 SP1
     *
     * @var \jamesiarmes\PEWS\Enumeration\IdFormatType
     */
    public $Format;
}
