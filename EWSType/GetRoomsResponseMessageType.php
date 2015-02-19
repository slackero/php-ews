<?php
/**
 * Contains EWSType_GetRoomsResponseMessageType.
 */

use jamesiarmes\PEWS\Type\ResponseMessageType;

/**
 * Represents the response to a GetRooms operation request.
 *
 * @package php-ews\Types
 */
class EWSType_GetRoomsResponseMessageType extends ResponseMessageType
{
    /**
     * Provides a list of email addresses and display names that represent
     * meeting rooms.
     *
     * @since Exchange 2010
     *
     * @var EWSType_ArrayOfRoomsType
     */
    public $Rooms;
}
