import logging
import logging.handlers

logger = logging.getLogger('AuthAPI')
handler = logging.handlers.SysLogHandler(address = '/dev/log')
logger.addHandler(handler)
