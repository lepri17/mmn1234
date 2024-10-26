from enum import Enum

class EResponseCode(Enum):
    Response_SUCCESS_REGISTRATION = 1600  # רישום הצליח
    Response_FAIL_REGISTRATION = 1601  # רישום נכשל
    Response_GET_SEND_PUBLIC_KEY = 1602  # התקבל מפתח ציבורי ושולח מפתח AES מוצפן
    Response_CRC_FILE_TRANSFER = 1603  # קובץ התקבל תקין CRC
    Response_CONF_MESSAGE = 1604  # מאושרת בקשת התחברות חוזרת
    Response_RECONNECT_CONF = 1605  # אישור התחברות חוזרת, שולח שוב את 1602
    Response_RECONNECT_IGNORE = 1606  # בקשה התחברות חוזרת נדחתה