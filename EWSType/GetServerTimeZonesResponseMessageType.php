<?php
/**
 * Contains EWSType_GetServerTimeZonesResponseMessageType.
 */

use jamesiarmes\PEWS\Type\ResponseMessageType;

/**
 * Represents the status and result of a single GetServerTimeZones operation
 * request.
 *
 * @package php-ews\Types
 */
class EWSType_GetServerTimeZonesResponseMessageType extends ResponseMessageType
{
    /**
     * Contains an array of time zone definitions.
     *
     * @since Exchange 2010
     *
     * @var EWSType_ArrayOfTimeZoneDefinitionType
     */
    public $TimeZoneDefinitions;
}
