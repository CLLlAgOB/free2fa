# config.py
# Copyright (C) 2024 Voloskov Aleksandr Nikolaevich

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

""" A module containing configuration parameters for an application. """

import os


class Config:
    """ A container class for storing configuration parameters. """
    # pylint: disable=too-few-public-methods
    # Telegram bot token
    TOKEN = os.environ.get("FREE2FA_TELEGRAM_BOT_TOKEN", "none")
    # Language of bot interface (ru or en)
    LANGUAGE = os.environ.get("FREE2FA_TELEGRAM_BOT_LANGUAGE", "ru")
    # Max message length from user
    MAX_MESSAGE_LENGTH = int(os.environ.get("FREE2FA_MAX_MESSAGE_LENGTH", 100))
    # Automatically creates users in the base while specifying telegram id 0
    AUTO_REG_ENABLED = os.environ.get(
        "FREE2FA_AUTO_REG_ENABLED", "false").lower() == "true"
    # Without confirmation to log in to the server
    # Allow access to the server for users with telegram ID 0
    BYPASS_ENABLED = os.environ.get(
        "FREE2FA_BYPASS_ENABLED", "false").lower() == "true"
    # How many seconds are given to respond
    # must also change the settings on the side of windows server
    # specifying the response timeout response radius server that FREE2FA_TIMEOUT +1 (11)
    FREE2FA_TIMEOUT = int(os.environ.get("FREE2FA_TIMEOUT", 10))
    # Allow all users without a push request if api.telegram.org is unavailable
    ALLOW_API_FAILURE_PASS = os.environ.get(
        "ALLOW_API_FAILURE_PASS", "false").lower() == "true"
