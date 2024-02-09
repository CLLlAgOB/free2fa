# en_en.py
# Copyright (C) 2024 Voloskov Aleksandr Nikolaevich

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
""" A container class for storing configuration parameters. """

MESSAGES = {
    "start": "Hello! Your telegram_id: {}.",
    "register_with_admin": "📱To register, contact the admin and provide your telegram_id.",
    "auth_request": ("🔐 Authorization request. If you did not attempt to log in, "
                     "reject the request and contact the administrator."),
    "was_auth_request": ("❌ A login attempt was made but was rejected due to a timeout. "
                         "If you have not attempted to log in, reject the request and "
                         "contact your administrator."),
    "action_accept": "\U0001f7e2 Approve",
    "action_reject": "\U0001f534 Reject"
}
